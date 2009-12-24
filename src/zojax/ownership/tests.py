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
import unittest, doctest
from zope import interface, component
from zope.app.testing import placelesssetup
from zope.annotation.attribute import AttributeAnnotations

import zope.security.management
from zope.security.interfaces import IPrincipal
from zojax.security import tests as sectests
from zojax.security.securitypolicy import SecurityPolicy

from zojax.ownership.owner import initObjectOwnership
from zojax.ownership.owner import Ownership, InheritedOwnership
from zojax.ownership.localroles import getLocalRoles, getGroupLocalRoles
from zojax.ownership.interfaces import IOwnership, IInheritOwnership


class Principal:
    interface.implements(IPrincipal)

    def __init__(self, id):
        self.id = id
        self.title = id
        self.groups = []

    def __repr__(self):
        return "<Principal '%s'>"%self.id

class Participation:
    interaction = None


def setUp(test):
    sectests.setUp(test)
    zope.security.management.setSecurityPolicy(SecurityPolicy)

    sm = component.getSiteManager()
    sm.registerAdapter(Ownership)
    sm.registerAdapter(InheritedOwnership, (IInheritOwnership,), IOwnership)
    sm.registerAdapter(getLocalRoles, name="zojax.ownership-owner")
    sm.registerAdapter(getGroupLocalRoles, name="zojax.ownership-groupowner")
    sm.registerAdapter(AttributeAnnotations)
    sm.registerHandler(initObjectOwnership)


def test_suite():
    return unittest.TestSuite((
            doctest.DocFileSuite(
                'README.txt',
                setUp=setUp, tearDown=placelesssetup.tearDown,
                optionflags=doctest.NORMALIZE_WHITESPACE|doctest.ELLIPSIS),
            ))
