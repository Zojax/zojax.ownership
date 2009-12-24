##############################################################################
#
# Copyright (c) 2009 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""

$Id$
"""
from zope import interface, component
from zope.component import queryUtility
from zope.app.security.interfaces import IUnauthenticatedPrincipal

from zojax.security.interfaces import IPrincipalGroups
from zojax.ownership.interfaces import IOwnerAware, IOwnership


@component.adapter(IOwnerAware)
@interface.implementer(IPrincipalGroups)
def principalGroups(content):
    owner = IOwnership(content).owner
    if owner is None:
        owner = queryUtility(IUnauthenticatedPrincipal)

    return IPrincipalGroups(owner, None)
