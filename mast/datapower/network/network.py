"""==========================================================
mast network:

A set of tools for automating routine network administration
tasks associated with IBM DataPower appliances.

Copyright 2014, All Rights Reserved
McIndi Solutions LLC
=========================================================="""
import flask
import urllib2
import commandr
from mast.plugins.web import Plugin
from pkg_resources import resource_string
import mast.datapower.datapower as datapower
from mast.logging import make_logger, logged
import mast.plugin_utils.plugin_utils as util
from functools import partial, update_wrapper
import mast.plugin_utils.plugin_functions as pf


cli = commandr.Commandr()

command = cli.command
Run = cli.Run
RunFunction = cli.RunFunction
SetOptions = cli.SetOptions
Usage = cli.Usage

# network tests
# =============
#
# These functions are meant to check the network functionality and
# connectivity of the specified appliances.
#
# current commands
# ----------------
# check-connectivity - Will check the connectivity from localhost to the
#                      xml mgmt, web mgmt and CLI
# tcp-connection-test - Will check the connectivity from the appliance to a
#                       given host/port pair


@logged("mast.datapower.network")
@cli.command('check-connectivity', category='network tests')
def check_connectivity(appliances=[], credentials=[],
                       timeout=120, web=False, no_check_hostname=False):
    """Check the connectivity of the three mgmt interfaces (xml, web and cli)
    on the specified appliances."""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to check connectivity of {}".format(str(env.appliances)))

    if web:
        return util.render_connectivity_table(env), util.render_history(env)

    print '\nhostname\t\txml\t\tweb\t\tcli'
    print '-' * 80
    for appliance in env.appliances:
        resp = []
        resp.append(appliance.hostname)
        xml = str(appliance.check_xml_mgmt())
        logger.debug("connectivity to xml mgmt interface: {}".format(xml))
        web = str(appliance.check_web_mgmt())
        logger.debug("connectivity to Web GUI: {}".format(web))
        cli = str(appliance.check_cli_mgmt())
        logger.debug("connectivity to cli mgmt interface: {}".format(cli))
        resp.append(xml)
        resp.append(web)
        resp.append(cli)
        print '\t\t'.join(resp)
    print


@logged("mast.datapower.network")
@cli.command('tcp-connection-test', category='network tests')
def tcp_connection_test(appliances=[], credentials=[],
                        timeout=120, remote_hosts=[],
                        remote_ports=[], web=False, no_check_hostname=False):
    """Perform a TCP Connection Test from each appliance to each remote_host
    at each remote_port

Parameters:

* remote_hosts - The remote hosts to test for connectivity
* remote_ports - The ports on the remote hosts to test"""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Performing TCP Connection Test from {} to {} on ports {}".format(
            str(env.appliances),
            str(remote_hosts),
            str(remote_ports)))

    if web:
        return util.render_tcp_connection_test_table(
            env, remote_hosts, remote_ports), util.render_history(env)

    print 'appliance\t\tremote host\tremote port\tSuccess\n'
    print '-' * 80
    for appliance in env.appliances:
        for host in remote_hosts:
            for port in remote_ports:
                resp = appliance.TCPConnectionTest(
                    RemoteHost=host,
                    RemotePort=port)
                success = bool(resp)
                logger.debug(
                    "Response from {} for test to {}:{}: {}".format(
                        appliance.hostname,
                        host,
                        port,
                        success))
                line = '{0}\t\t{1}\t{2}\t\t{3}'.format(
                    appliance.hostname,
                    host,
                    port,
                    str(success))
                print line
#
# ~#~#~#~#~#~#~#

# ~#~#~#~#~#~#~#
# Network Configuration
# =====================
#
# These functions are meant to ease the network configuration of multiple
# DataPower appliances.
#
# current commands
# ----------------
# add-host-alias
# del-host-alias
# add-secondary-address
# del-secondary-address
# add-static-host
# del-static-host
# add-static-route
# del-static-route
#


# TODO: clean up web output (maybe into a seperate function call)
@logged("mast.datapower.network")
@cli.command("display-routing-table", category="network config")
def display_routing_table(appliances=[], credentials=[],
                          timeout=120, web=False,
                          no_check_hostname=False):
    """Display the routing table for the specified appliances

__NOTE__: This will try the RoutingStatus3 status provider and
it will fall back to RoutingStatus2 if the appliance doesn't
support RoutingStatus3.'"""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to retrieve routing table from {}".format(
            str(env.appliances)))

    # try RoutingStatus3 first
    try:
        logger.debug("Attempting RoutingStatus3")
        resp = env.perform_action(
            "get_status",
            domain="default",
            provider="RoutingStatus3")
        xpath = datapower.STATUS_XPATH + "RoutingStatus3"
    except urllib2.HTTPError:
        logger.warn(
            "RoutingStatus3 unavailable, falling back to RoutingStatus2")
        resp = env.perform_action(
            "get_status",
            domain="default",
            provider="RoutingStatus2")
        xpath = datapower.STATUS_XPATH + "RoutingStatus2"
    logger.debug("Response received: {}".format(resp))

    header_row = []
    for host, l in resp.items():
        if not web:
            print host, "\n", "=" * len(host), "\n"
        fields = [child.tag for child in l.xml.find(xpath)]

        if web:
            if not header_row:
                header_row = list(fields)
                header_row.insert(0, "Appliance")
                rows = []

        width = len(max(fields, key=len))
        template = "{:<{width}} " * len(fields)
        header = template.format(*fields, width=width)
        if not web:
            print header

        for item in l.xml.findall(xpath):
            values = [child.text for child in item]
            line = template.format(*values, width=width)
            if web:
                _row = list(values)
                _row.insert(0, host)
                rows.append(_row)
            if not web:
                print line
    if web:
        return flask.render_template(
            "results_table.html",
            header_row=header_row,
            rows=rows), util.render_history(env)
        print


@logged("mast.datapower.network")
@cli.command('display-ethernet-interface', category='network config')
def display_ethernet_interface(appliances=[], credentials=[], timeout=120,
                               EthernetInterface="", persisted=True,
                               web=False, no_check_hostname=False):
    """This will display the details of the specified ethernet interface
on the specified appliances.

Parameters:

* EthernetInterface - The EthernetInterface to examine
* persisted - Whether to get the persisted configuration, otherwise
the running configuration will be returned"""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout=120,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to Retrieve EthernetInterface configuration for "
        "{} {}".format(
            str(env.appliances), EthernetInterface))

    resp = env.perform_action(
        "get_config",
        _class="EthernetInterface",
        name=EthernetInterface,
        persisted=persisted)
    logger.debug("Response received: {}".format(str(resp)))
    if web:
        return (
            util.render_ethernet_interface_results_table(resp),
            util.render_history(env))
    for host, r in resp.items():
        print host, "\n", "=" * len(host), "\n"
        print r
        print


@logged("mast.datapower.network")
@cli.command('list-host-aliases', category='network config')
def list_host_aliases(appliances=[], credentials=[],
                      timeout=120, web=False,
                      no_check_hostname=False):
    """Lists the host aliases of the specified appliances as well as
the host aliases common to all specified appliances."""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info(
        "Attempting to find host aliases for {}".format(
            str(env.appliances)))

    resp = env.perform_action('get_host_aliases')
    logger.debug("Received Responses: {}".format(str(resp)))

    if web:
        return util.render_host_alias_table(resp), util.render_history(env)

    sets = []
    for host, l in resp.items():
        sets.append(set(l))
        print host
        print "=" * len(host)
        for item in l:
            print " ".join(item)
        print

    common = sets[0].intersection(*sets[1:])
    logger.info("Host Aliases common to {}: {}".format(
        str(env.appliances),
        str(common)))
    print '\n', "common\n", "=" * len("common")
    for item in common:
        print " ".join(item)


@logged("mast.datapower.network")
@cli.command('add-host-alias', category='network config')
def add_host_alias(appliances=[], credentials=[],
                   timeout=120, save_config=False,
                   name=None, ip=None,
                   admin_state='enabled', web=False,
                   no_check_hostname=False):
    """Adds a host alias to the specified appliances.

Parameters:

* save-config - If specified the configuration will be saved after adding
the host alias
* name - The name of the host alias
* ip - The IP address for the host alias
* admin-state - The admin state for the host alias (enabled or disabled)"""
    logger = make_logger("mast.network")
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    logger.info("Attempting to add host alias {} {} to {}".format(
        name, ip, str(env.appliances)))

    kwargs = {'name': name, 'ip': ip, 'admin_state': admin_state}
    resp = env.perform_async_action('add_host_alias', **kwargs)
    logger.debug("Responses received: {}".format(str(resp)))

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="add_host_alias")

    if save_config:
        kwargs = {'domain': 'default'}
        resp = env.perform_async_action('SaveConfig', **kwargs)
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('del-host-alias', category='network config')
def del_host_alias(appliances=[], credentials=[],
                   timeout=120, save_config=False,
                   HostAlias="", web=False, no_check_hostname=False):
    """Removes a host alias from the specified appliances.

Parameters:

* save-config - If specified the configuration will be saved after
removing the host alias
* HostAlias - The name of the host alias to remove"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {'name': HostAlias}
    resp = env.perform_async_action('del_host_alias', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="del_host_alias")

    if save_config:
        kwargs = {'domain': 'default'}
        env.perform_async_action('SaveConfig', **kwargs)
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('list-secondary-addresses', category='network config')
def list_secondary_addresses(appliances=[], credentials=[],
                             timeout=120, EthernetInterface="",
                             web=False, no_check_hostname=False):
    """This will list the secondary IP Addresses on the specified
Ethernet Interface for the specified appliances.

Parameters:

* EthernetInterface - The ethernet interface to examine for secondary
addresses"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    kwargs = {'interface': EthernetInterface}

    resp = env.perform_action('get_secondary_addresses', **kwargs)

    if web:
        return util.render_secondary_address_table(
            resp), util.render_history(env)

    for host, l in resp.items():
        print host
        print '=' * len(host), '\n'
        for item in l:
            print item
        print


@logged("mast.datapower.network")
@cli.command('add-secondary-address', category='network config')
def add_secondary_address(appliances=[], credentials=[],
                          timeout=120, save_config=False,
                          EthernetInterface="",
                          secondary_address=None, web=False,
                          no_check_hostname=False):
    """Adds a secondary IP address to the specified appliances on the
specified ethernet interface

Parameters:

* save-config - If specified the configuration will be saved after
adding the host alias
* EthernetInterface- The ethernet interface to which to add the
secondary address
* secondary-address - The secondary IP address to add to the ethernet
interface"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        'ethernet_interface': EthernetInterface,
        'secondary_address': secondary_address}
    resp = env.perform_async_action('add_secondary_address', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="add_secondary_address")

    if save_config:
        kwargs = {'domain': 'default'}
        env.perform_async_action('SaveConfig', **kwargs)
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('del-secondary-address', category='network config')
def del_secondary_address(appliances=[], credentials=[],
                          timeout=120, save_config=False,
                          EthernetInterface="",
                          secondary_address=None, web=False,
                          no_check_hostname=False):
    """Removes a secondary IP address from the specified appliances on the
specified ethernet interface

Parameters:

* save-config - If specified the configuration will be saved after
adding the host alias
* EthernetInterface - The ethernet interface to remove the
secondary address from
* secondary-address - The secondary IP address to remove from the
ethernet interface"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    kwargs = {
        'ethernet_interface': EthernetInterface,
        'secondary_address': secondary_address}
    resp = env.perform_async_action('del_secondary_address', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="del_secondary_address")

    if save_config:
        kwargs = {'domain': 'default'}
        env.perform_async_action('SaveConfig', **kwargs)
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('list-static-hosts', category='network config')
def list_static_hosts(appliances=[], credentials=[],
                      timeout=120, web=False,
                      no_check_hostname=False):
    """This will list the static hosts on the specified appliances."""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    resp = env.perform_async_action('get_static_hosts')

    if web:
        return util.render_static_hosts_table(resp), util.render_history(env)

    for host, l in resp.items():
        print host
        print '=' * len(host)
        print
        for item in l:
            print ' - '.join(item)
        print


@logged("mast.datapower.network")
@cli.command('add-static-host', category='network config')
def add_static_host(appliances=[], credentials=[],
                    timeout=120, save_config=False,
                    hostname=None, ip=None, web=False,
                    no_check_hostname=False):
    """Adds a static host to  the specified appliances

Parameters:

* save-config - If specified the configuration will be saved after adding
the host alias
* hostname - The hostname of the static host
* ip - The IP address of the static host"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        'hostname': hostname,
        'ip': ip}
    resp = env.perform_async_action('add_static_host', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="add_static_host")

    if save_config:
        kwargs = {'domain': 'default'}
        env.perform_async_action('SaveConfig', **kwargs)
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('del-static-host', category='network config')
def del_static_host(appliances=[], credentials=[],
                    timeout=120, save_config=False,
                    hostname=None, web=False,
                    no_check_hostname=False):
    """Removes a static host from the specified appliances

Parameters:

* save-config - If specified the configuration will be saved after adding
the host alias
* hostname - The hostname of the static host"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    resp = env.perform_async_action(
        'del_static_host',
        **{'hostname': hostname})

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="del_static_host")

    if save_config:
        resp = env.perform_async_action('SaveConfig', **{'domain': 'default'})
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save_config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('list-static-routes', category='network config')
def list_static_routes(appliances=[], credentials=[], timeout=120,
                       EthernetInterface="", web=False,
                       no_check_hostname=False):
    """This will list all of the static routes on the specified
EthernetInterface on the specified appliances.

Parameters:

* EthernetInterface - The EthernetInterface to examine fir static routes"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)

    kwargs = {'interface': EthernetInterface}
    resp = env.perform_action('get_static_routes', **kwargs)

    if web:
        return util.render_static_routes_table(resp), util.render_history(env)

    for host, l in resp.items():
        print host
        print '=' * len(host)
        print
        for item in l:
            print ' - '.join(item)
        print


@logged("mast.datapower.network")
@cli.command('add-static-route', category='network config')
def add_static_route(appliances=[], credentials=[],
                     timeout=120, save_config=False,
                     EthernetInterface="", destination=None,
                     gateway=None, metric='0', web=False,
                     no_check_hostname=False):
    """Adds a static route to the specified appliance on the specified
ethernet interface

Parameters:

* save-config - If specified the configuration will be saved after adding
the host alias
* EthernetInterface - The ethernet interface to add the static route to
* destination - The destination for the static route
* gateway - The gateway to use for this static route
* metric - Set the metric (priority) for this static route.
(The higher the metric the more prefered that route will be)"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        'ethernet_interface': EthernetInterface,
        'destination': destination,
        'gateway': gateway,
        'metric': metric}
    resp = env.perform_async_action('add_static_route', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="add_static_route")

    if save_config:
        env.perform_async_action('SaveConfig', **{'domain': 'default'})
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save config")
    if web:
        return output, util.render_history(env)


@logged("mast.datapower.network")
@cli.command('del-static-route', category='network config')
def del_static_route(appliances=[], credentials=[],
                     timeout=120, save_config=False,
                     EthernetInterface="", destination=None,
                     web=False, no_check_hostname=False):
    """Removes a static route from the specified appliance on the specified
ethernet interface

Parameters:

* save-config - If specified the configuration will be saved after removing
the host alias
* EthernetInterface - The ethernet interface to remove the static route from
* destination - The destination for the static route to be removed"""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {
        'ethernet_interface': EthernetInterface,
        'destination': destination}
    resp = env.perform_async_action('del_static_route', **kwargs)

    if web:
        output = util.render_boolean_results_table(
            resp, suffix="del_static_route")

    if save_config:
        env.perform_async_action('SaveConfig', **{'domain': 'default'})
        if web:
            output += util.render_boolean_results_table(
                resp, suffix="save config")
    if web:
        return output, util.render_history(env)
#
# ~#~#~#~#~#~#~#


# ~#~#~#~#~#~#~#
# Caches
# ======
#
# These functions are meant to be used to flush the caches that DataPower
# maintains.
#
# Current Commands:
# ----------------
#
# FlushArpCache()
# FlushDNSCache()
# FlushNDCache()
# FlushPDPCache(XACMLPDP)
#

@logged("mast.datapower.network")
@cli.command('flush-arp-cache', category='caches')
def flush_arp_cache(appliances=[], credentials=[],
                    timeout=120, web=False, no_check_hostname=False):
    """This will flush the ARP Cache on the specified appliances."""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    responses = env.perform_action('FlushArpCache')

    if web:
        return util.render_boolean_results_table(
            responses), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@logged("mast.datapower.network")
@cli.command('flush-dns-cache', category='caches')
def flush_dns_cache(appliances=[], credentials=[],
                    timeout=120, web=False, no_check_hostname=False):
    """This will flush the DNS Cache for the specified appliances."""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    responses = env.perform_action('FlushDNSCache')

    if web:
        return util.render_boolean_results_table(
            responses), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@logged("mast.datapower.network")
@cli.command('flush-nd-cache', category='caches')
def flush_nd_cache(appliances=[], credentials=[],
                   timeout=120, web=False, no_check_hostname=False):
    """This will flush the ND cache on the specified appliances."""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    responses = env.perform_action('FlushNDCache')

    if web:
        return util.render_boolean_results_table(
            responses), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


@logged("mast.datapower.network")
@cli.command('flush-pdp-cache', category='caches')
def flush_pdp_cache(appliances=[], credentials=[],
                    timeout=120, XACMLPDP="",
                    web=False, no_check_hostname=False):
    """This will flush the PDP cache on the specified appliances
for the specified XACMLPDP."""
    check_hostname = not no_check_hostname
    env = datapower.Environment(
        appliances,
        credentials,
        timeout,
        check_hostname=check_hostname)
    kwargs = {"XACMLPDP": XACMLPDP}
    responses = env.perform_action('FlushPDPCache', **kwargs)

    if web:
        return util.render_boolean_results_table(
            responses), util.render_history(env)

    for host, response in list(responses.items()):
        if response:
            print
            print host
            print '=' * len(host)
            if response:
                print 'OK'
            else:
                print "FAILURE"
                print response


def get_data_file(f):
    return resource_string(__name__, 'docroot/{}'.format(f))


class WebPlugin(Plugin):
    def __init__(self):
        self.route = partial(pf.handle, "network")
        self.route.__name__ = "network"
        self.html = partial(pf.html, "mast.datapower.network")
        update_wrapper(self.html, pf.html)

    def css(self):
        return get_data_file('plugin.css')

    def js(self):
        return get_data_file('plugin.js')


if __name__ == '__main__':
    try:
        cli.Run()
    except AttributeError, e:
        if "'NoneType' object has no attribute 'app'" in e:
            raise NotImplementedError(
                "HTML formatted output is not supported on the CLI")
