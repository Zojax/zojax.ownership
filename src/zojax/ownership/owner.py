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
from rwproperty import getproperty, setproperty

from zope import event, interface, component
from zope.annotation.interfaces import IAnnotations
from zope.component.interfaces import ComponentLookupError
from zope.lifecycleevent.interfaces import IObjectCreatedEvent

from zope.security.proxy import removeSecurityProxy
from zope.security.interfaces import IPrincipal, IGroup

from zojax.security.utils import getPrincipal

from zojax.ownership import interfaces
from zojax.ownership.interfaces import IOwnership
from zojax.ownership.interfaces import IInheritOwnership
from zojax.ownership.interfaces import IUnchangeableOwnership
from zojax.ownership.interfaces import OwnerChangedEvent

ANNOTATION_KEY = 'zojax.ownership.Owner'


class Ownership(object):
    component.adapts(interfaces.IOwnerAware)
    interface.implements(IOwnership)

    _ownerId = ''
    isGroup = False

    def __init__(self, context):
        annotations = IAnnotations(removeSecurityProxy(context))

        self.context = context
        self.annotations = annotations

        ownerinfo = annotations.get(ANNOTATION_KEY)
        if ownerinfo is None:
            ownerinfo = {'ownerId': None, 'isGroup': False}
            annotations[ANNOTATION_KEY] = ownerinfo

        self._ownerId = ownerinfo['ownerId']
        self.isGroup = ownerinfo['isGroup']

    @setproperty
    def owner(self, owner):
        if IPrincipal.providedBy(owner):
            oldOwner = self.owner

            self._ownerId = owner.id
            self.isGroup = IGroup.providedBy(owner)

            self.annotations[ANNOTATION_KEY] = {'ownerId': self._ownerId,
                                                'isGroup': self.isGroup}

            event.notify(OwnerChangedEvent(self.context, owner, oldOwner))
        else:
            raise ValueError('IPrincipal object is required.')

    @getproperty
    def owner(self):
        if self._ownerId:
            return getPrincipal(self._ownerId)
        else:
            return None

    @getproperty
    def ownerId(self):
        return self._ownerId

    @setproperty
    def ownerId(self, pid):
        self.owner = getPrincipal(pid)


class InheritedOwnership(object):
    component.adapts(interfaces.IInheritOwnership)
    interface.implements(IOwnership, IUnchangeableOwnership)

    def __init__(self, context):
        parent = context

        while IInheritOwnership.providedBy(parent):
            parent = getattr(parent, '__parent__', None)
            if parent is None:
                raise ComponentLookupError()

        self._owner = IOwnership(parent)

    @property
    def owner(self):
        return self._owner.owner

    @property
    def ownerId(self):
        return self._owner.ownerId


@component.adapter(interfaces.IOwnerAware, IObjectCreatedEvent)
def initObjectOwnership(object, event):
    if interfaces.IUnchangeableOwnership.providedBy(object) or \
            interfaces.IInheritOwnership.providedBy(object):
        return

    principal = getPrincipal()
    if principal is not None:
        interfaces.IOwnership(removeSecurityProxy(object)).owner = principal
