#!/usr/bin/env python3
"""Validate one private JSON result, or adb instrumentation output containing it."""
import copy
import json
import re
import sys
from pathlib import Path

PACKAGE = 'org.rcsrs.admissionprobe'
PERMISSIONS = {
    'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'READ_PRIVILEGED_PHONE_STATE',
    'USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER', 'USE_ICC_AUTH', 'INTERNET',
    'ACCESS_NETWORK_STATE', 'CHANGE_NETWORK_STATE',
}
FEATURES = {'telephony', 'telephony_subscription', 'ims', 'ims_single_registration'}


def exact_keys(value, expected):
    assert type(value) is dict and set(value) == expected, 'unexpected/missing object keys'


def read_status(value, available=False):
    assert type(value) is dict, 'read result must be an object'
    status = value.get('status')
    if status in {'denied', 'unavailable'}:
        exact_keys(value, {'status', 'exception'})
        assert type(value['exception']) is str and re.fullmatch(
            r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+', value['exception'], re.ASCII
        ), 'invalid exception class'
        assert len(value['exception']) <= 256, 'exception class too long'
    elif available:
        exact_keys(value, {'status', 'value'})
        assert status == 'available' and type(value['value']) is bool, 'invalid boolean read'
    else:
        exact_keys(value, {'status'})
        assert status in {'present', 'absent'}, 'invalid presence status'


def check(result):
    exact_keys(result, {
        'schema_version', 'package', 'instrumentation_package', 'target_package',
        'certificate_sha1', 'version_code', 'version_name', 'sdk_int', 'uid',
        'default_sms', 'permissions', 'features', 'carrier_privileges', 'readings',
    })
    assert type(result['schema_version']) is int and result['schema_version'] == 1
    for key in ('package', 'instrumentation_package', 'target_package'):
        assert result[key] == PACKAGE, 'unexpected package identity'
    assert type(result['certificate_sha1']) is str and re.fullmatch(
        '[0-9a-f]{40}', result['certificate_sha1']), 'invalid signing certificate digest'
    assert type(result['version_code']) is int and result['version_code'] == 1
    assert result['version_name'] == '0.1.0'
    assert type(result['sdk_int']) is int and 29 <= result['sdk_int'] <= 1000
    assert type(result['uid']) is int and result['uid'] >= 10000, 'privileged UID forbidden'
    assert result['uid'] % 100000 >= 10000, 'non-application UID forbidden'
    assert type(result['default_sms']) is bool and not result['default_sms'], 'probe must not hold SMS role'
    exact_keys(result['permissions'], PERMISSIONS)
    exact_keys(result['features'], FEATURES)
    assert all(type(v) is bool for v in result['permissions'].values()), 'permission must be boolean'
    assert all(type(v) is bool for v in result['features'].values()), 'feature must be boolean'
    read_status(result['carrier_privileges'], available=True)
    exact_keys(result['readings'], {'imsi', 'imei', 'own_number'})
    for value in result['readings'].values():
        read_status(value)


def self_test():
    valid = {
        'schema_version': 1, 'package': PACKAGE, 'instrumentation_package': PACKAGE,
        'target_package': PACKAGE, 'certificate_sha1': 'ab' * 20,
        'version_code': 1, 'version_name': '0.1.0', 'sdk_int': 36, 'uid': 10123,
        'default_sms': False, 'permissions': dict.fromkeys(PERMISSIONS, False),
        'features': dict.fromkeys(FEATURES, False),
        'carrier_privileges': {'status': 'available', 'value': False},
        'readings': {'imsi': {'status': 'denied', 'exception': 'java.lang.SecurityException'},
                     'imei': {'status': 'unavailable', 'exception': 'java.lang.UnsupportedOperationException'},
                     'own_number': {'status': 'present'}},
    }
    check(valid)
    invalid = []
    for key, value in [('uid', 0), ('uid', 2000), ('uid', 1000 + 100000),
                       ('package', 'org.example.other'), ('target_package', 'org.example.other'),
                       ('instrumentation_package', 'org.example.other'), ('uid', True),
                       ('version_code', '1'), ('default_sms', True), ('certificate_sha1', 'bad')]:
        case = copy.deepcopy(valid)
        case[key] = value
        invalid.append(case)
    case = copy.deepcopy(valid)
    case['readings']['imsi'] = '001010123456789'  # Synthetic raw value must be rejected.
    invalid.append(case)
    case = copy.deepcopy(valid)
    case['readings']['imsi']['value'] = '001010123456789'
    invalid.append(case)
    case = copy.deepcopy(valid)
    case['unexpected'] = 'forbidden'
    invalid.append(case)
    case = copy.deepcopy(valid)
    case['permissions']['READ_PHONE_STATE'] = 'true'
    invalid.append(case)
    case = copy.deepcopy(valid)
    case['readings']['own_number'] = {'status': 'success'}
    invalid.append(case)
    invalid.append({})
    for case in invalid:
        try:
            check(case)
        except AssertionError:
            continue
        raise AssertionError('invalid synthetic result accepted')
    print('PASS: synthetic contract self-test (1 accepted, %d rejected)' % len(invalid))


def main():
    if not __debug__:
        raise ValueError('validation requires enabled assertions')
    if sys.argv[1:] == ['--self-test']:
        self_test()
        return
    assert len(sys.argv) <= 2, 'expected one input file'
    text = Path(sys.argv[1]).read_text() if len(sys.argv) == 2 else sys.stdin.read()
    markers = [line.split('rcs_admission=', 1)[1] for line in text.splitlines()
               if line.startswith('INSTRUMENTATION_RESULT: rcs_admission=')]
    if markers:
        assert len(markers) == 1, 'expected exactly one instrumentation JSON result'
        text = markers[0]
    check(json.loads(text))
    print('PASS: ordinary-app admission result contract')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, ValueError, OSError, IndexError):
        print('FAIL: missing or invalid whitelisted admission result', file=sys.stderr)
        sys.exit(1)
