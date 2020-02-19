from datadog_checks.pihole import PiholeCheck


def test_check(aggregator, instance):
    check = PiholeCheck('pihole', {}, {})
    check.check(instance)

    aggregator.assert_all_metrics_covered()
