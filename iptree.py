#!/usr/bin/env python3
#
# IRAS - Internet Routing Analysis System
# Copyright (C) 2014-2018 Tomas Hlavacek (tmshlvck@gmail.com)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

import ipaddress


class _IPLookupTreeNode(object):
    """ Internal Node for the IPLookupTree. Should not be
    even public unless cPickle needs it. How unfortunate... """
    def __init__(self):
        self.one=None # _IPLookupTreeNode or None
        self.zero=None # _IPLookupTreeNode or None
        self.end=None # ipaddress.IP46Network
        self.data=None # cave pickle
    
class IPLookupTree(object):
    """ Lookup tree for holding list of IP (IPv4/IPv6) prefixes. """
    def __init__(self,ipv6=False):
        """
        :param bool ipv6: IPv6 flag
        """
        self.ipv6=ipv6
        self.root=_IPLookupTreeNode()

    @staticmethod
    def _bits(chararray):
        """ Convert 8-bit chars to list of bools (bits)
        :param chararray: 8-bit chars
        :returns: Iterator that yields bits
        """
        for c in chararray:
            for i in range(7,-1,-1):
                if c & (1 << i):
                    yield True
                else:
                    yield False

    def add(self,net,data):
        """ Add node to the tree.

        :param net: IPv4/6 prefix
        :param data: Bound data (arbitrary) object
        """
    
        net = IPLookupTree._normalize_pfx(net)
        bits = list(IPLookupTree._bits(net.network_address.packed))
        index=self.root
        for bi in range(0,net.prefixlen):
            if bits[bi]:
                if not index.one:
                    index.one = _IPLookupTreeNode()
                index = index.one
            else:
                if not index.zero:
                    index.zero = _IPLookupTreeNode()
                index = index.zero
        index.end = net
        index.data = data

    @staticmethod
    def _normalize_pfx(ip):
        """
            Create IPv4Network or IPv6Network out of a supplied prefix in the input string
            or IPv4/6Address object.
        """
        if isinstance(ip, ipaddress.IPv4Network) or isinstance(ip, ipaddress.IPv6Network):
            return ip
        else:
            return ipaddress.ip_network(ip)

    @staticmethod
    def _normalize_addr(ip):
        """
            Create IPv4Address or IPv6Address out of a supplied IPv46Network, string or address.
        """
        if isinstance(ip, ipaddress.IPv4Address) or isinstance(ip, ipaddress.IPv6Address):
            return ip
        elif isinstance(ip, ipaddress.IPv4Network) or isinstance(ip, ipaddress.IPv6Network):
            return ip.network_address
        else:
            return ipaddress.ip_address(ip)

    def _lookupAllLevelsNode(self, ip, maxMatches=0):
        """ Internal match helper.

        :param ip: IPv4/6 to match
        :param int maxMatches: Maximum matches in the return list, i.e. stop when we \
        have #maxMatches matches and ignore more specifices. 0=Unlimited
        :returns: List of resulting match candidate objects.
        """

        ip = IPLookupTree._normalize_pfx(ip)
        limit=ip.prefixlen

        index = self.root
        # match address
        a = IPLookupTree._normalize_addr(ip)
        for (bi,b) in enumerate(IPLookupTree._bits(a.packed)):
            if index.end and index.end.overlaps(ip): # match
                yield index

            if bi >= limit or (maxMatches > 0 and len(candidates) >= maxMatches):
                # limit reached - either pfxlen or maxMatches
                return

            # choose next step 1 or 0
            if b:
                index = index.one
            else:
                index = index.zero

            # dead end
            if not index: 
                return
        # in case full IP address was matched in the tree simply finish with the last yield

    def lookupAllLevels(self, ip, maxMatches=0):
        """ Lookup in the tree. Find all matches (i.e. all objects that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) Return all the results in a form of
        list. The first is the least specific match and the last is the most
        specific one.

        :param ip: IPv4/6 to match
        :param int maxMatches: Maximum matches in the return list, i.e. stop when we \
        have #maxMatches matches and ignore more specifices. 0=Unlimited
        :returns: List of resulting data in matching nodes.
        """
        return [n.data for n in self._lookupAllLevelsNode(ip, maxMatches)]

    def lookupFirst(self, ip):
        """ Lookup in the tree. Find the first match (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.)

        :param ip: IPv4/6 to match
        :returns: Resulting data in first matching node.
        """

        result = self.lookupAllLevels(ip, 1)
        if result:
            return result[0]
        else:
            return None

    
    def lookupBest(self, ip):
        """ Lookup in the tree. Find the most specific match (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) It is pretty much the same the routing
        mechanisms are doing.

        :param ip: IPv4/6 to match
        :returns: Resulting data in best matching node.
        """
        
        result = self.lookupAllLevels(ip)
        if result:
            return result[-1]
        else:
            return None

    def lookupNetExact(self, net):
        """ Lookup in the tree. Find the exact match for a net (i.e. an object that
        has some network set in a tree node and the network contains the
        IP/Network that is being matched.) It is pretty much the same the routing
        mechanisms are doing.

        :param net: IPv4/6 prefix to match
        :returns: Resulting data in exact matching node.
        """

        return [r.data for r in self._lookupAllLevelsNode(net) if r.end.prefixlen == ipaddress.ip_network(net).prefixlen]

    def dump(self):
        """ Dump the tree. """
        
        def printSubtree(node):
            """ Print subtree of the IPLookupTree.
            :param node: Root to print (recursively)
            """

            if not node:
                return
            
            if node.end:
                print('%s %s' %(str(node.end), str(node.data)))
                
            printSubtree(node.zero)
            printSubtree(node.one)

        printSubtree(self.root)

    def __contains__(self, key):
        try:
            return self.lookupBest(key) != None
        except:
            return False


