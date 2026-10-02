!------------------------------------------------------------------------------
!  NetTalk_ARMiLogin.inc  -  WebAuthn / passkey (fingerprint, Face ID, ...) login
!                            support for NetTalk web servers.
!
!  Server side relying-party logic only: challenge generation, parsing of
!  authenticatorData / clientDataJSON, ES256 signature verification through
!  Windows CNG (bcrypt.dll) and a small TopSpeed credential store.
!  It has NO dependency on NetTalk, so it can be used from any Clarion program.
!
!  Everything that travels is base64url text (no padding), as WebAuthn does.
!------------------------------------------------------------------------------

  OMIT('_EndOfInclude_',_NetTalkARMiLoginPresent_)
_NetTalkARMiLoginPresent_  EQUATE(1)

! ---- where the class lives (Multi-DLL) ----
! The NetTalk_ARMiLogin template defines these two project constants in every app (or define them by hand):
!   stand-alone app / root DLL that exports the class : NetTalkARMiLoginLinkMode=>1  NetTalkARMiLoginDllMode=>0   (class compiled into this app)
!   DLL or EXE that uses the class from the root DLL  : NetTalkARMiLoginLinkMode=>0  NetTalkARMiLoginDllMode=>1   (class imported from the DLL)
! They have no default on purpose: a default cannot be told apart from a defined 0 and would override the project value.

WA:MaxStr              EQUATE(2048)           ! working buffer size for every blob handled

WA:Ok                  EQUATE(0)
WA:Err:BadInput        EQUATE(1)
WA:Err:ClientData      EQUATE(2)              ! type / challenge / origin mismatch
WA:Err:RpIdHash        EQUATE(3)
WA:Err:Flags           EQUATE(4)              ! user presence / verification missing
WA:Err:Unknown         EQUATE(5)              ! credential id not registered
WA:Err:Signature       EQUATE(6)
WA:Err:Counter         EQUATE(7)              ! signature counter went backwards (cloned key?)
WA:Err:Crypto          EQUATE(8)              ! CNG call failed
WA:Err:Store           EQUATE(9)              ! credential file error

NetWebAuthnClass       CLASS,TYPE,MODULE('NetTalk_ARMiLogin.clw'),LINK('NetTalk_ARMiLogin.clw',NetTalkARMiLoginLinkMode),DLL(NetTalkARMiLoginDllMode)
! ---- configuration (set by Init) ----
RpId                     CSTRING(256)         ! domain, no port, e.g. 'portit.com.ar'
RpName                   CSTRING(100)         ! friendly name shown by the device
Origin                   CSTRING(256)         ! expected origin, e.g. 'https://portit.com.ar'
FileName                 CSTRING(260)         ! credential store (TopSpeed)
RequireUV                BYTE                 ! 1 = fingerprint/PIN must have been verified
LastError                LONG                 ! WA:Err:... of the last Verify call
LastErrorText            CSTRING(200)

Init                     PROCEDURE(STRING pRpId,STRING pRpName,STRING pOrigin,STRING pFileName,BYTE pRequireUV=1)

! ---- helpers exposed because the templates use them ----
NewChallenge             PROCEDURE(),STRING             ! 32 random bytes, base64url
Base64UrlEncode          PROCEDURE(STRING pBin,LONG pLen),STRING
Base64UrlDecode          PROCEDURE(STRING pText,*STRING pBin),LONG   ! returns bytes written, 0 on error
JsonString               PROCEDURE(STRING pText),STRING              ! "text" with JSON escaping
JsonField                PROCEDURE(STRING pJson,STRING pName),STRING ! value of a top level "name":"value"
Sha256                   PROCEDURE(STRING pData,LONG pLen,*STRING pHash),LONG  ! 32 bytes in pHash, 0 = ok

! ---- relying party operations (all return WA:Ok on success) ----
RegistrationOptions      PROCEDURE(STRING pChallenge,STRING pUserKey),STRING   ! JSON for the browser
LoginOptions             PROCEDURE(STRING pChallenge),STRING                   ! JSON for the browser
VerifyRegistration       PROCEDURE(STRING pChallenge,STRING pCredId,STRING pClientData,STRING pAuthData,STRING pPublicKey,STRING pUserKey,STRING pDevice),LONG
VerifyAssertion          PROCEDURE(STRING pChallenge,STRING pCredId,STRING pClientData,STRING pAuthData,STRING pSignature,*STRING pUserKey),LONG

! ---- credential store ----
OpenStore                PROCEDURE(),LONG
CloseStore               PROCEDURE()
ListCredentialIds        PROCEDURE(STRING pUserKey),STRING         ! JSON array body: "id1","id2"
CountCredentials         PROCEDURE(STRING pUserKey),LONG
DeleteCredentials        PROCEDURE(STRING pUserKey)

! ---- internal ----
SetError                 PROCEDURE(LONG pCode,STRING pText),LONG,PROC
ImportPublicKey          PROCEDURE(STRING pSpki,LONG pSpkiLen,*LONG pKeyHandle,*LONG pAlgHandle),LONG
DerToRaw                 PROCEDURE(STRING pDer,LONG pDerLen,*STRING pRaw),LONG
CheckClientData          PROCEDURE(STRING pType,STRING pChallenge,STRING pClientData),LONG
CheckAuthData            PROCEDURE(STRING pAuthData,LONG pAuthLen,*REAL pSignCount),LONG
                       END

  _EndOfInclude_
