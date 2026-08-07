import pathlib
import unittest


LUA_PATH = pathlib.Path(__file__).parent / "conf" / "lua.local.d" / "smg_ingest.lua"
RSPAMD_LOCAL_PATH = pathlib.Path(__file__).parent / "conf" / "rspamd.conf.local"
RSPAMD_GROUPS_PATH = pathlib.Path(__file__).parent / "conf" / "local.d" / "groups.conf"
POSTFIX_MAIN_PATH = pathlib.Path(__file__).parents[1] / "postfix" / "main.cf"


class IngestMilterContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = LUA_PATH.read_text(encoding="utf-8")

    def test_quarantine_sets_discard_before_fallible_bookkeeping(self):
        branch = self.source.index('accepted.disposition == "quarantined"')
        discard = self.source.index('task:set_pre_result("discard"', branch)
        insert = self.source.index('task:insert_result("SMG_QUARANTINED"', branch)
        cache = self.source.index('task:cache_set("smg_mail_event_response"', branch)
        self.assertLess(discard, insert)
        self.assertLess(discard, cache)

    def test_reject_sets_terminal_action_before_fallible_bookkeeping(self):
        branch = self.source.index('accepted.disposition == "rejected"')
        reject = self.source.index('task:set_pre_result("reject"', branch)
        insert = self.source.index('task:insert_result("SMG_REJECTED"', branch)
        cache = self.source.index('task:cache_set("smg_mail_event_response"', branch)
        self.assertLess(reject, insert)
        self.assertLess(reject, cache)

    def test_inserted_symbols_are_registered_as_virtual_symbols(self):
        groups = RSPAMD_GROUPS_PATH.read_text(encoding="utf-8")
        for name in (
            "SMG_SENDER_ALLOWLIST",
            "SMG_SENDER_BLACKLIST",
            "SMG_QUARANTINED",
            "SMG_REJECTED",
            "SMG_TAGGED",
        ):
            registration = f'register_virtual_symbol("{name}"'
            insertion = f'task:insert_result("{name}"'
            self.assertIn(registration, self.source)
            self.assertIn(insertion, self.source)
            registration_tail = self.source[self.source.rindex(registration):]
            self.assertIn("1.0,", registration_tail)
            self.assertIn(f'"{name}"', groups)

    def test_lua_local_plugin_is_not_explicitly_loaded_twice(self):
        local_config = RSPAMD_LOCAL_PATH.read_text(encoding="utf-8")
        self.assertNotIn('lua = "/etc/rspamd/lua.local.d/smg_ingest.lua"', local_config)

    def test_coroutine_http_callbacks_are_not_wrapped_in_pcall(self):
        callbacks = self.source[self.source.index("local sender_policy_symbol"):]
        self.assertNotIn("local ok, err = pcall(function()", callbacks)

    def test_milter_errors_tempfail_instead_of_bypassing_scanning(self):
        postfix_config = POSTFIX_MAIN_PATH.read_text(encoding="utf-8")
        self.assertIn("milter_default_action = tempfail", postfix_config)


if __name__ == "__main__":
    unittest.main()
