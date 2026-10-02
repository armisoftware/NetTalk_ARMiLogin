#TEMPLATE(NetTalk_ARMiLogin,'NetTalk ARMi Login - fingerprint / passkey (WebAuthn) login for NetTalk web servers'),FAMILY('ABC')
#!------------------------------------------------------------------------------
#!  NetTalk_ARMiLogin.tpl
#!
#!  Three extensions:
#!    NetTalk_ARMiLogin_Global   (application)   declares the class + credential store
#!    NetTalk_ARMiLogin_Form     (NetWebForm)    "Login with fingerprint" button + login service
#!    NetTalk_ARMiLogin_Offer    (NetWebPage...) offers to activate the fingerprint after a normal login
#!
#!  Files:  NetTalk_ARMiLogin.inc/.clw  (Clarion LibSrc)   NetTalk_ARMiLogin.js (web\scripts)
#!------------------------------------------------------------------------------
#INCLUDE('NetTalk_ARMiLogin.tpw')
