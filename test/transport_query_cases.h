#ifndef DSSH_TRANSPORT_QUERY_CASES_H
#define DSSH_TRANSPORT_QUERY_CASES_H

struct query_snapshot_probe {
	dssh_session sess;
	dssh_kex kex;
	dssh_key_algo key;
	dssh_enc enc;
	dssh_mac mac;
	atomic_bool entered;
	atomic_bool stop;
	_Atomic uint32_t cycles;
};

/* Model negotiation publishing and clearing descriptors. Their registry owners
 * remain alive until the query worker has joined and the session is retired. */
static int
query_snapshot_publish(void *opaque)
{
	struct query_snapshot_probe *probe = opaque;
	while (!atomic_load(&probe->stop)) {
		atomic_store(&probe->sess->trans.kex_selected, NULL);
		atomic_store(&probe->sess->trans.key_algo_selected, NULL);
		atomic_store(&probe->sess->trans.enc_c2s_selected, NULL);
		atomic_store(&probe->sess->trans.mac_c2s_selected, NULL);
		atomic_store(&probe->sess->trans.kex_selected, probe->kex);
		atomic_store(&probe->sess->trans.key_algo_selected, probe->key);
		atomic_store(&probe->sess->trans.enc_c2s_selected, probe->enc);
		atomic_store(&probe->sess->trans.mac_c2s_selected, probe->mac);
		if (atomic_load(&probe->cycles) != UINT32_MAX)
			atomic_fetch_add(&probe->cycles, 1);
		atomic_store(&probe->entered, true);
	}
	return 0;
}

static int
test_query_snapshot(void)
{
	dssh_test_reset_global_config();
	ASSERT_OK(register_all_algorithms());
	ASSERT_OK(dssh_transport_set_callbacks(mock_tx_dispatch, mock_rx_dispatch,
	    mock_rxline_dispatch, mock_extra_line_cb));
	dssh_session sess = dssh_session_init(true, 0);
	ASSERT_NOT_NULL(sess);
	struct query_snapshot_probe probe = { .sess = sess, .kex = gconf.kex_head,
	    .key = gconf.key_algo_head, .enc = gconf.enc_head, .mac = gconf.mac_head };
	atomic_init(&probe.entered, false);
	atomic_init(&probe.stop, false);
	atomic_init(&probe.cycles, 0);
	const char *(*getters[])(dssh_session) = {
	    dssh_transport_get_kex_name, dssh_transport_get_hostkey_name,
	    dssh_transport_get_enc_name, dssh_transport_get_mac_name
	};
	const char *names[] = { probe.kex->name, probe.key->name,
	    probe.enc->name, probe.mac->name };
	thrd_t worker;
	int created = thrd_create(&worker, query_snapshot_publish, &probe);
	bool valid = created == thrd_success;
	if (valid)
		valid = dssh_test_wait_bool(&probe.entered, true);
	uint32_t checks = 0;
	for (uint32_t round = 0; round < UINT32_C(100000) && valid; round++) {
		for (size_t i = 0; i < sizeof(getters) / sizeof(getters[0]); i++) {
			const char *name = getters[i](sess);
			checks++;
			/* Inspect only pointer identity until the known immutable owner is
			 * established; an unexpected pointer is never dereferenced. */
			if (name != NULL && name != names[i]) {
				valid = false;
				break;
			}
		}
	}
	atomic_store(&probe.stop, true);
	if (created == thrd_success && thrd_join(worker, NULL) != thrd_success)
		abort();
	uint32_t cycles = atomic_load(&probe.cycles);
	dssh_session_cleanup(sess);
	dssh_test_reset_global_config();
	ASSERT_TRUE(valid);
	ASSERT_EQ_U(checks, UINT32_C(400000));
	ASSERT_TRUE(cycles > 0);
	return TEST_PASS;
}

#endif
