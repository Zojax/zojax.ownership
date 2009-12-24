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
""" zojax.ownership interfaces

$Id$
"""
from zope import interface
from zope.security.interfaces import IPrincipal
from zope.component.interfaces import ObjectEvent, IObjectEvent


class IOwnerAware(interface.Interface):
    """ marker interface for objects that supports ownership """


class IOwnerGroupAware(IOwnerAware):
    """ marker interface for objects that supports group ownership """


class IInheritOwnership(interface.Interface):
    """ marker interface for object that can inherit
    ownership information from parent """


class IUnchangeableOwnership(interface.Interface):
    """ marker interface """


class IOwnership(interface.Interface):
    """ ownership information """

    owner = interface.Attribute(u'IPrincipal object')

    ownerId = interface.Attribute(u'Principal id')

    isGroup = interface.Attribute(u'Is owner group')


class IOwnerChangedEvent(IObjectEvent):
    """ owner of object changed """

    newOwner = interface.Attribute('New owner')

    oldOwner = interface.Attribute('Old owner')


class OwnerChangedEvent(ObjectEvent):
    interface.implements(IOwnerChangedEvent)

    def __init__(self, object, newOwner, oldOwner):
        self.object = object
        self.newOwner = newOwner
        self.oldOwner = oldOwner
