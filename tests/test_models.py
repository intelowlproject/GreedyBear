from greedybear.models import IocType, Statistics, ViewType

from . import CustomTestCase


class ModelsTestCase(CustomTestCase):
    def test_ioc_model(self):
        self.assertEqual(self.ioc.name, "140.246.171.141")
        self.assertEqual(self.ioc.type, IocType.IP.value)
        self.assertEqual(self.ioc.first_seen, self.current_time)
        self.assertEqual(self.ioc.last_seen, self.current_time)
        self.assertEqual(self.ioc.days_seen, [self.current_time])
        self.assertEqual(self.ioc.number_of_days_seen, 1)
        self.assertEqual(self.ioc.attack_count, 1)
        self.assertEqual(self.ioc.interaction_count, 1)
        self.assertEqual(self.ioc.scanner, True)
        self.assertEqual(self.ioc.payload_request, True)
        self.assertEqual(self.ioc.related_urls, [])
        self.assertEqual(self.ioc.ip_reputation, "")
        self.assertEqual(self.ioc.asn, "12345")
        self.assertEqual(self.ioc.destination_ports, [22, 23, 24])
        self.assertEqual(self.ioc.login_attempts, 1)
        self.assertEqual(self.ioc.recurrence_probability, 0.1)
        self.assertEqual(self.ioc.expected_interactions, 11.1)

        self.assertEqual(self.ioc_2.ip_reputation, "mass scanner")

        # Test general_honeypot M2M relationship (unified model)
        self.assertIn(self.cowrie, self.ioc.general_honeypot.all())
        self.assertIn(self.log4pot, self.ioc.general_honeypot.all())
        self.assertIn(self.heralding, self.ioc.general_honeypot.all())
        self.assertIn(self.ciscoasa, self.ioc.general_honeypot.all())

    def test_command_sequence_model(self):
        self.assertEqual(self.command_sequence.first_seen, self.current_time)
        self.assertEqual(self.command_sequence.last_seen, self.current_time)
        self.assertEqual(self.command_sequence.commands, self.cmd_seq)
        self.assertEqual(self.command_sequence.commands_hash, self.hash)
        self.assertEqual(self.command_sequence.cluster, 11)

    def test_cowrie_session_model(self):
        self.assertEqual(self.cowrie_session.session_id, int("ffffffffffff", 16))
        self.assertEqual(self.cowrie_session.start_time, self.current_time)
        self.assertEqual(self.cowrie_session.duration, 1.234)
        self.assertEqual(self.cowrie_session.login_attempt, True)
        self.assertEqual(self.cowrie_session.credentials, ["root | root"])
        self.assertEqual(self.cowrie_session.command_execution, True)
        self.assertEqual(self.cowrie_session.interaction_count, 5)
        self.assertEqual(self.cowrie_session.source.name, "140.246.171.141")
        self.assertEqual(self.cowrie_session.commands.commands, self.cmd_seq)

    def test_statistics_model(self):
        self.statistic = Statistics.objects.create(
            source="140.246.171.141",
            view=ViewType.ENRICHMENT_VIEW.value,
            request_date=self.current_time,
        )
        self.assertEqual(self.statistic.source, "140.246.171.141")
        self.assertEqual(self.statistic.view, ViewType.ENRICHMENT_VIEW.value)
        self.assertEqual(self.statistic.request_date, self.current_time)

    def test_general_honeypot_model(self):
        self.assertEqual(self.heralding.name, "Heralding")
        self.assertEqual(self.heralding.active, True)
