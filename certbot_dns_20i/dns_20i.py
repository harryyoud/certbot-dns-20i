import json
import os

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from requests.exceptions import HTTPError
from twentyi_api import TwentyIRestAPI, APIError


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for 20i
    This Authenticator uses the 20i API to fulfill a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record if you are using 20i for DNS'
    ttl = 10

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.dns_api = None
        self.auth = None
        self._zone_id = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(add, default_propagation_seconds=10)
        add('credentials', help='Path to 20i credential JSON file.', default=None)

    def _setup_credentials(self):
        if self.conf('credentials') is None:
            if token := os.environ.get('TWENTYI_BEARER_TOKEN', None) is None:
                raise errors.PluginError('No credentials given. Please configure credentials'
                                         'using --dns-20i-credentials <file> or setting'
                                         'TWENTYI_BEARER_TOKEN in your environment')
            self.auth = {'bearer': token}
        else:
            self._configure_file('credentials', 'path to 20i credential JSON file')
            dns_common.validate_file_permissions(self.conf('credentials'))
            with open(self.conf('credentials'), 'r') as f:
                self.auth = json.load(f)
        self.dns_api = TwentyIDns(self.auth)

    def _perform(self, domain, validation_name, validation):
        zone = self._get_zone_id_for_domain(domain)
        record_name = self._split_record_name(validation_name, zone)
        self.dns_api.add_txt_record(zone, record_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        zone = self._get_zone_id_for_domain(domain)
        record_name = self._split_record_name(validation_name, zone)
        self.dns_api.del_txt_record(zone, record_name, validation)

    def _split_record_name(self, full_name, zone):
        if full_name.endswith(zone):
            return full_name[:-(len(zone) + 1)]  # len + 1 is for a dot
        else:
            raise errors.PluginError('Record name is not a prefix of domain zone')

    def _get_zone_id_for_domain(self, domain):
        """Find the zone id responsible a given FQDN.
           That is, the id for the zone whose name is the longest parent of the
           domain.
        """
        if self._zone_id is not None:
            return self._zone_id

        self._zone_id = self._find_zone_id_for_domain(domain)
        return self._zone_id

    def _find_zone_id_for_domain(self, domain):
        candidate_zones = f'_acme_challenge.{domain}'.rstrip(".").split(".")

        for candidate in ['.'.join(candidate_zones[i:]) for i in range(0, len(candidate_zones))]:
            try:
                self.dns_api.get_domain_info(candidate)
                return candidate
            except (HTTPError, APIError):
                continue
        raise errors.PluginError("Unable to find a 20i hosted zone for {0}".format(domain))

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
                "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
                + "the 20i Reseller REST API."
        )


class TwentyIDns(object):
    def __init__(self, auth):
        self._api = TwentyIRestAPI(auth=auth)

    def add_txt_record(self, zone, record_name, record_content):
        """
        Adds a TXT record using supplied information

        :param str zone:
        :param str record_name: Record name without the zone on the end (for hello.world.domain.com,
                                it would be "hello.world" if the zone were "domain.com"
        :param str record_content:
        :raises certbot.errors.PluginError: if an error occurs communicating with the 20i API
        """
        dns = self._api.get(f'/domain/{zone}/dns')
        for record in dns['records']:
            if record['host'] == '.'.join([record_name, zone]):
                print(f'Found an existing acme_challenge record for {zone}. Continuing anyway')
        try:
            self._api.post(f'/domain/{zone}/dns', {
                'new': {
                    'TXT': [
                        {
                            'host': record_name if record_name else '@',
                            'txt': record_content,
                        }
                    ]
                }
            })
        except HTTPError as e:
            raise errors.PluginError(f"Failed to add TXT record {record_name} on {zone}", e)

    def del_txt_record(self, zone, record_name, record_content):
        """
        Adds a TXT record using supplied information

        :param str zone:
        :param str record_name: Record name without the zone on the end (for hello.world.domain.com,
                                it would be "hello.world" if the zone were "domain.com"
        :param str record_content:
        :raises certbot.errors.PluginError: if an error occurs communicating with the 20i API
        """
        dns = self._api.get(f'/domain/{zone}/dns')
        records = list(filter(lambda x:
                              x['type'] == 'TXT' and
                              x['host'] == '.'.join([record_name, zone]) and
                              x['txt'] == record_content,
                              dns['records']
                              ))

        if len(records) != 1:
            print(f"Expecting to find 1 record to delete, found {len(records)}. Deleting only the first one")

        ref = records[0]['ref']
        self._api.post(f'/domain/{zone}/dns', {
            'delete': [
                ref
            ]
        })

    def get_domain_info(self, domain):
        """
        Return information about a domain
        Also useful as a check for whether the zone is hosted on 20i

        :param domain:
        :return: dict
        :raises requests.exceptions.HTTPError:
        """
        return self._api.get(f'/domain/{domain}')
