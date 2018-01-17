#!/bin/python

#
# The MIT License (MIT)
#
# Copyright (c) 2015 JP Senior jp.senior@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# This file is used to configure a list of feeds a user is interested in acquiiring
feeds = [

    dict(
        type='alienvault',
        url='https://reputation.alienvault.com/reputation.data',
        source='AlienVault',
        itype='Misc.',
        description='AlienVault Reputation'),
    dict(
        type='spamhaus',
        url='https://www.spamhaus.org/drop/drop.txt',
        source='Spamhaus',
        itype='Spam',
        description='Spamhaus NETMASK Drop'),
    dict(
        type='talos',
        url='http://www.talosintel.com/feeds/ip-filter.blf',
        source='Talos Intel',
        itype='Misc.',
        description='Talos Intel malicious IPs'),
    dict(
        type='malcode',
        url='http://malc0de.com/bl/IP_Blacklist.txt',
        itype='Misc',
        source='Malc0de',
        description='Amalc0de.com IPs'),
    dict(
        type='bambenek',
        url='http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt',
        itype='C&C',
        source='Bambenek',
        description='Bambenek IPs'),
    dict(
        type='emerging-compromised',
        url='http://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        source='Emerging Threats',
        itype='Misc.',
        description='emergingthreats.net Compromised IPs'),
    dict(
        type='feodo',
        url='https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
        source='Abuse.ch Feodo',
        itype='C&C',
        description='abuse.ch feodo Blacklist'),
    dict(
        type='binarydefense',
        url='http://www.binarydefense.com/banlist.txt',
        source='Binary Defence',
        itype='Misc.',
        description='Binary Defense Systems Banlist'),
    dict(
        type='ssl-blacklist',
        url='https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
        source='Abuse.ch SSL',
        itype='SSL',
        description='abuse.ch SSL Blacklist'),
    dict(
        type='zeus',
        url='https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist',
        source='Abuse.ch Zeus',
        itype='C&C',
        description='abuse.ch Zeus tracker'),
    dict(
        type='nothink-ssh',
        url='http://www.nothink.org/blacklist/blacklist_ssh_all.txt',
        source='NoThink',
        itype='SSH',
        description='nothink SSH Blacklist'),
    dict(
        type='malwaredomain',
        url='http://www.malwaredomainlist.com/hostslist/ip.txt',
        source='malwaredomainlist.com',
        itype='Misc.',
        description='malwaredomainlist IP'),
    dict(
        type='cinscore-badguys',
        url='http://cinsscore.com/list/ci-badguys.txt',
        source='CINS',
        itype='Misc.',
        description='ciarmy IP'),
    dict(
        type='tor-exitnodes',
        url='https://check.torproject.org/exit-addresses',
        source='Tor Project',
        itype='Tor',
        description='Tor ExitNode IPs'),
    dict(
        type='autoshun',
        url='http://autoshun.org/files/shunlist.csv',
        source='Autoshun',
        itype='Unknown',
        description='Autoshun list'),
]
