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
from zope.securitypolicy.interfaces import IPrincipalRoleMap
from zope.securitypolicy.interfaces import Allow, Unset, Deny

from interfaces import \
     IOwnership, IInheritOwnership, IOwnerAware, IOwnerGroupAware


@component.adapter(IOwnerAware)
@interface.implementer(IPrincipalRoleMap)
def getLocalRoles(context):
    if IInheritOwnership.providedBy(context):
        return

    owner = IOwnership(context)
    if owner.isGroup and IOwnerGroupAware.providedBy(context):
        return
    return LocalRoles(context, owner)


class LocalRoles(object):
    interface.implements(IPrincipalRoleMap)

    def __init__(self, context, owner):
        self.owner = owner
        self.ownerId = owner.ownerId or u''

    def getPrincipalsForRole(self, role_id):
        if (role_id == 'content.Owner'):
            return ((self.ownerId, Allow),)
        else:
            return ()

    def getRolesForPrincipal(self, principal_id,
                             deny = (('content.Owner', Deny),),
                             allow = (('content.Owner', Allow),)):
        if principal_id == self.ownerId:
            return allow
        else:
            return deny

    def getSetting(self, role_id, principal_id):
        if (principal_id == self.ownerId) and (role_id == 'content.Owner'):
            return Allow
        else:
            return Deny

    def getPrincipalsAndRoles(self):
        return ()


@component.adapter(IOwnerGroupAware)
@interface.implementer(IPrincipalRoleMap)
def getGroupLocalRoles(context):
    if IInheritOwnership.providedBy(context):
        return

    owner = IOwnership(context)
    if owner.isGroup:
        return GroupLocalRoles(context, owner)


class GroupLocalRoles(object):
    interface.implements(IPrincipalRoleMap)

    def __init__(self, context, owner):
        self.owner = owner
        self.ownerId = owner.ownerId

    def getPrincipalsForRole(self, role_id):
        if role_id == 'content.GroupOwner':
            return ((self.ownerId, Allow),)
        else:
            return ()

    def getRolesForPrincipal(self, principal_id,
                             deny = (('content.GroupOwner', Deny),),
                             allow = (('content.GroupOwner', Allow),)):
        if principal_id == self.ownerId:
            return allow
        else:
            return deny

    def getSetting(self, role_id, principal_id):
        if (principal_id == self.ownerId) and (role_id == 'content.GroupOwner'):
            return Allow
        else:
            return Deny

    def getPrincipalsAndRoles(self):
        return ()
