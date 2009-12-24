=================
Content ownership
=================

This package implement single ownership concept. Content owner has special
role on content `content.Owner`.

We need setup security interaction and principals

  >>> from zope import interface, component, event
  >>> import zope.security.management
  >>> from zojax.ownership import tests, interfaces
  >>> from zojax.ownership.interfaces import IOwnership
  >>> from zojax.ownership.interfaces import IOwnerAware, IOwnerGroupAware

  >>> from zope.app.security.interfaces import IAuthentication
 
  >>> principal1 = tests.Principal('bob')
  >>> principal2 = tests.Principal('meg')

  >>> class Auth(object):
  ...    interface.implements(IAuthentication)
  ...
  ...    def getPrincipal(self, id):
  ...       if id == 'bob':
  ...          return principal1
  ...       if id == 'meg':
  ...          return principal2

  >>> auth = Auth()
  >>> component.provideUtility(auth)

  >>> participation = tests.Participation()
  >>> participation.principal = principal1
  >>> zope.security.management.endInteraction()
  >>> zope.security.management.newInteraction(participation)
  >>> interaction = zope.security.management.getInteraction()

  >>> from zope.location import Location
  >>> from zope.lifecycleevent import ObjectCreatedEvent
  >>> from zope.annotation.interfaces import IAttributeAnnotatable

  >>> class IMyObject(IOwnerAware):
  ...   pass

  >>> class Content(Location):
  ...    interface.implements(IAttributeAnnotatable, IMyObject)
  ...    
  ...    def __init__(self, parent=None):
  ...        self.__parent__ = parent

  >>> content = Content()
  >>> event.notify(ObjectCreatedEvent(content))

  >>> owner = IOwnership(content)

  >>> owner.owner
  <Principal 'bob'>

  >>> owner.ownerId
  'bob'

Now let's check owner roles

  >>> from zojax.security.interfaces import IExtendedGrantInfo

  >>> grantinfo = IExtendedGrantInfo(content)
  >>> grantinfo.getPrincipalsForRole('content.Owner')
  [('bob', PermissionSetting: Allow)]

  >>> grantinfo.getRolesForPrincipal('bob')
  [('content.Owner', PermissionSetting: Allow)]

  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Deny)]

We can change owner

  >>> owner.owner = principal2

  >>> owner = IOwnership(content)

  >>> owner.owner
  <Principal 'meg'>

  >>> owner.ownerId
  'meg'

Change ownerId

  >>> owner.ownerId = 'bob'

  >>> owner = IOwnership(content)
  >>> owner.owner
  <Principal 'bob'>

  >>> owner.owner = principal2

  >>> grantinfo = IExtendedGrantInfo(content)
  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Allow)]

  >>> grantinfo.getRolesForPrincipal('bob')
  [('content.Owner', PermissionSetting: Deny)]

  >>> grantinfo.getPrincipalsForRole('unknown.Role')
  []

content.Owner and content.GroupOwner are disabled for principal bob 
so ownership is not inherited from parents. But we can change this, we should 
explicitly set marker interface for content

  >>> from zojax.ownership.interfaces import IInheritOwnership
  >>> interface.directlyProvides(content, IInheritOwnership)

  >>> grantinfo = IExtendedGrantInfo(content)
  >>> grantinfo.getRolesForPrincipal('bob')
  []

  >>> interface.noLongerProvides(content, IInheritOwnership)


We can assign only IPrincipal object

  >>> owner.owner = object()
  Traceback (most recent call last):
  ...
  ValueError: IPrincipal object is required.


Chain owner
-----------

let's create content chain, content -> content1 -> content2

  >>> content1 = Content(content)
  >>> content2 = Content(content1)

  >>> grantinfo = IExtendedGrantInfo(content1)
  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Deny)]
  >>> grantinfo.getRolesForPrincipal('bob')
  [('content.Owner', PermissionSetting: Deny)]

now mark content1 as IInheritOwnership

  >>> interface.directlyProvides(content1, IInheritOwnership)

  >>> grantinfo = IExtendedGrantInfo(content1)
  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Allow)]

  >>> ownership = IOwnership(content1)
  >>> ownership.ownerId
  'meg'

  >>> interfaces.IUnchangeableOwnership.providedBy(ownership)
  True

  >>> ownership.ownerId = 'bob'
  Traceback (most recent call last):
  ...
  AttributeError: can't set attribute

content2

  >>> grantinfo = IExtendedGrantInfo(content2)
  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Deny)]

  >>> interface.directlyProvides(content2, IInheritOwnership)
  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Allow)]

  >>> IOwnership(content2).ownerId
  'meg'
  >>> IOwnership(content2).owner
  <Principal 'meg'>

  >>> IOwnership(content).ownerId = 'bob'
  >>> IOwnership(content1).ownerId
  'bob'
  >>> IOwnership(content2).ownerId
  'bob'

  >>> IExtendedGrantInfo(content1).getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Deny)]
  >>> IExtendedGrantInfo(content1).getRolesForPrincipal('bob')
  [('content.Owner', PermissionSetting: Allow)]
  >>> IExtendedGrantInfo(content2).getRolesForPrincipal('meg')
  [('content.Owner', PermissionSetting: Deny)]
  >>> IExtendedGrantInfo(content2).getRolesForPrincipal('bob')
  [('content.Owner', PermissionSetting: Allow)]

We need IOwnerAware parent for IInheritOwnership objects

  >>> content4 = Content()
  >>> interface.directlyProvides(content4, IInheritOwnership)
  >>> IOwnership(content4)
  Traceback (most recent call last):
  ...
  ComponentLookupError

just tests

  >>> from zope.securitypolicy.interfaces import IPrincipalRoleMap
  >>> map = component.getAdapter(content, IPrincipalRoleMap, 'zojax.ownership-owner')
  >>> map.getRolesForPrincipal('bob')
  (('content.Owner', PermissionSetting: Allow),)
  >>> map.getSetting('content.Owner', 'bob')
  PermissionSetting: Allow
  >>> map.getSetting('content.Owner', 'meg')
  PermissionSetting: Deny


Group owner
-----------

  >>> from zope.security.interfaces import IGroup
  >>> interface.directlyProvides(principal1, IGroup)

  >>> owner = IOwnership(content)
  >>> owner.owner = principal1

  >>> owner = IOwnership(content)
  >>> owner.isGroup
  True

  >>> interface.directlyProvides(content, IOwnerGroupAware)

  >>> grantinfo = IExtendedGrantInfo(content)
  >>> grantinfo.getRolesForPrincipal('bob')
  [('content.GroupOwner', PermissionSetting: Allow)]

  >>> grantinfo.getPrincipalsForRole('content.GroupOwner')
  [('bob', PermissionSetting: Allow)]

  >>> grantinfo.getPrincipalsForRole('unknown.Role')
  []

  >>> grantinfo.getRolesForPrincipal('meg')
  [('content.GroupOwner', PermissionSetting: Deny)]


just tests

  >>> map = component.getAdapter(content, IPrincipalRoleMap, 'zojax.ownership-groupowner')
  >>> map.getRolesForPrincipal('bob')
  (('content.GroupOwner', PermissionSetting: Allow),)
  >>> map.getSetting('content.GroupOwner', 'bob')
  PermissionSetting: Allow
  >>> map.getSetting('content.GroupOwner', 'meg')
  PermissionSetting: Deny
