!------------------------------------------------------------------------------
!  NetTalk_ARMiLogin.clw  -  see NetTalk_ARMiLogin.inc
!
!  Needs bcrypt.lib (import library of the Windows CNG bcrypt.dll), installed in
!  <Clarion>\accessory\lib - the NetTalk_ARMiLogin template adds it to the project.
!------------------------------------------------------------------------------
  MEMBER()

  INCLUDE('NetTalk_ARMiLogin.inc'),ONCE

  MAP
    MODULE('bcrypt')
wa_BCryptOpenAlgorithmProvider PROCEDURE(LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptOpenAlgorithmProvider')
wa_BCryptCloseAlgorithmProvider PROCEDURE(LONG,LONG),LONG,PASCAL,PROC,NAME('BCryptCloseAlgorithmProvider')
wa_BCryptGetProperty PROCEDURE(LONG,LONG,LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptGetProperty')
wa_BCryptCreateHash PROCEDURE(LONG,LONG,LONG,LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptCreateHash')
wa_BCryptHashData PROCEDURE(LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptHashData')
wa_BCryptFinishHash PROCEDURE(LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptFinishHash')
wa_BCryptDestroyHash PROCEDURE(LONG),LONG,PASCAL,PROC,NAME('BCryptDestroyHash')
wa_BCryptImportKeyPair PROCEDURE(LONG,LONG,LONG,LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptImportKeyPair')
wa_BCryptVerifySignature PROCEDURE(LONG,LONG,LONG,LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptVerifySignature')
wa_BCryptDestroyKey PROCEDURE(LONG),LONG,PASCAL,PROC,NAME('BCryptDestroyKey')
wa_BCryptGenRandom PROCEDURE(LONG,LONG,LONG,LONG),LONG,PASCAL,NAME('BCryptGenRandom')
    END
  END

! ---- UTF-16 names CNG wants (each char followed by a zero, double zero at the end) ----
WSha256              STRING('S<0>H<0>A<0>2<0>5<0>6<0><0><0>')
WEcdsaP256           STRING('E<0>C<0>D<0>S<0>A<0>_<0>P<0>2<0>5<0>6<0><0><0>')
WEccPublicBlob       STRING('E<0>C<0>C<0>P<0>U<0>B<0>L<0>I<0>C<0>B<0>L<0>O<0>B<0><0><0>')
WObjectLength        STRING('O<0>b<0>j<0>e<0>c<0>t<0>L<0>e<0>n<0>g<0>t<0>h<0><0><0>')

! fixed 26 byte header of an ES256 (P-256) SubjectPublicKeyInfo; byte 27 is 04 (uncompressed point)
SpkiHead             STRING('<48><89><48><19><6><7><42><134><72><206><61><2><1><6><8><42><134><72><206><61><3><1><7><3><66><0>')
B64Alphabet          STRING('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')

WAFileName           STRING(260),THREAD                  ! per thread: the store is opened by many web threads at once

WACred               FILE,DRIVER('TOPSPEED'),PRE(WAC),CREATE,BINDABLE,THREAD,NAME(WAFileName)
ByCred                 KEY(WAC:CredId),PRIMARY
ByUser                 KEY(WAC:UserKey),DUP,NOCASE
Record                 RECORD
CredId                   STRING(256)
UserKey                  STRING(255)
PublicKey                STRING(160)
SignCount                ULONG
Device                   STRING(60)
Created                  LONG
CreatedTime              LONG
LastUsed                 LONG
                       END
                     END

!==============================================================================
NetWebAuthnClass.Init PROCEDURE(STRING pRpId,STRING pRpName,STRING pOrigin,STRING pFileName,BYTE pRequireUV)
  CODE
  SELF.RpId      = CLIP(pRpId)
  SELF.RpName    = CLIP(pRpName)
  SELF.Origin    = CLIP(pOrigin)
  SELF.FileName  = CLIP(pFileName)
  SELF.RequireUV = pRequireUV
  WAFileName     = CLIP(pFileName)
  RETURN

!==============================================================================
NetWebAuthnClass.SetError PROCEDURE(LONG pCode,STRING pText)
  CODE
  SELF.LastError     = pCode
  SELF.LastErrorText = CLIP(pText)
  RETURN pCode

!==============================================================================
! base64url helpers
!==============================================================================
NetWebAuthnClass.Base64UrlEncode PROCEDURE(STRING pBin,LONG pLen)
Out    STRING(WA:MaxStr * 2)
O      LONG
I      LONG
B1     LONG
B2     LONG
B3     LONG
  CODE
  LOOP I = 1 TO pLen BY 3
    B1 = VAL(pBin[I])
    B2 = 0
    B3 = 0
    IF I + 1 <= pLen THEN B2 = VAL(pBin[I + 1]).
    IF I + 2 <= pLen THEN B3 = VAL(pBin[I + 2]).
    O += 1
    Out[O] = B64Alphabet[BSHIFT(B1,-2) + 1]
    O += 1
    Out[O] = B64Alphabet[BOR(BSHIFT(BAND(B1,3),4),BSHIFT(B2,-4)) + 1]
    IF I + 1 <= pLen
      O += 1
      Out[O] = B64Alphabet[BOR(BSHIFT(BAND(B2,15),2),BSHIFT(B3,-6)) + 1]
    END
    IF I + 2 <= pLen
      O += 1
      Out[O] = B64Alphabet[BAND(B3,63) + 1]
    END
  END
  IF O = 0 THEN RETURN ''.
  RETURN Out[1 : O]

!==============================================================================
NetWebAuthnClass.Base64UrlDecode PROCEDURE(STRING pText,*STRING pBin)
I      LONG
N      LONG
O      LONG
V      LONG
Acc    LONG
Bits   LONG
C      STRING(1)
  CODE
  N = LEN(CLIP(pText))
  LOOP I = 1 TO N
    C = pText[I]
    CASE C
    OF '='
      BREAK
    OF '+'
      V = 62
    OF '/'
      V = 63
    ELSE
      V = INSTRING(C,B64Alphabet,1,1) - 1
    END
    IF V < 0 THEN RETURN 0.
    Acc  = BOR(BSHIFT(Acc,6),V)
    Bits += 6
    IF Bits >= 8
      Bits -= 8
      O += 1
      IF O > SIZE(pBin) THEN RETURN 0.
      pBin[O] = CHR(BAND(BSHIFT(Acc,-Bits),255))
      Acc = BAND(Acc,BSHIFT(1,Bits) - 1)
    END
  END
  RETURN O

!==============================================================================
NetWebAuthnClass.JsonString PROCEDURE(STRING pText)
Out    STRING(1024)
O      LONG
I      LONG
C      STRING(1)
  CODE
  O = 1
  Out[1] = '"'
  LOOP I = 1 TO LEN(CLIP(pText))
    C = pText[I]
    IF VAL(C) < 32 THEN CYCLE.
    IF O > 1000 THEN BREAK.
    IF C = '"' OR C = '\'
      O += 1
      Out[O] = '\'
    END
    O += 1
    Out[O] = C
  END
  O += 1
  Out[O] = '"'
  RETURN Out[1 : O]

!==============================================================================
! value of a "name":"value" pair (no escapes handled: type / challenge / origin never have them)
NetWebAuthnClass.JsonField PROCEDURE(STRING pJson,STRING pName)
Pos    LONG
P      LONG
Q      LONG
  CODE
  Pos = INSTRING('"' & CLIP(pName) & '"',pJson,1,1)
  IF Pos = 0 THEN RETURN ''.
  P = Pos + LEN(CLIP(pName)) + 2
  LOOP WHILE P <= LEN(CLIP(pJson)) AND (pJson[P] = ' ' OR pJson[P] = ':')
    P += 1
  END
  IF P > LEN(CLIP(pJson)) OR pJson[P] <> '"' THEN RETURN ''.
  P += 1
  Q = INSTRING('"',pJson,1,P)
  IF Q = 0 THEN RETURN ''.
  IF Q = P THEN RETURN ''.
  RETURN pJson[P : Q - 1]

!==============================================================================
! CNG
!==============================================================================
NetWebAuthnClass.Sha256 PROCEDURE(STRING pData,LONG pLen,*STRING pHash)
hAlg   LONG
hHash  LONG
ObjLen LONG
CbRes  LONG
Obj    &STRING
St     LONG
Rc     LONG
  CODE
  IF pLen < 0 THEN RETURN SELF.SetError(WA:Err:BadInput,'sha256 length').
  St = wa_BCryptOpenAlgorithmProvider(ADDRESS(hAlg),ADDRESS(WSha256),0,0)
  IF St <> 0 THEN RETURN SELF.SetError(WA:Err:Crypto,'BCryptOpenAlgorithmProvider(SHA256)').
  St = wa_BCryptGetProperty(hAlg,ADDRESS(WObjectLength),ADDRESS(ObjLen),4,ADDRESS(CbRes),0)
  IF St <> 0 OR ObjLen <= 0
    wa_BCryptCloseAlgorithmProvider(hAlg,0)
    RETURN SELF.SetError(WA:Err:Crypto,'BCryptGetProperty(ObjectLength)')
  END
  Obj &= NEW STRING(ObjLen)
  Rc = WA:Ok
  St = wa_BCryptCreateHash(hAlg,ADDRESS(hHash),ADDRESS(Obj),ObjLen,0,0,0)
  IF St <> 0
    Rc = SELF.SetError(WA:Err:Crypto,'BCryptCreateHash')
  ELSE
    IF pLen > 0
      St = wa_BCryptHashData(hHash,ADDRESS(pData),pLen,0)
      IF St <> 0 THEN Rc = SELF.SetError(WA:Err:Crypto,'BCryptHashData').
    END
    IF Rc = WA:Ok
      St = wa_BCryptFinishHash(hHash,ADDRESS(pHash),32,0)
      IF St <> 0 THEN Rc = SELF.SetError(WA:Err:Crypto,'BCryptFinishHash').
    END
    wa_BCryptDestroyHash(hHash)
  END
  DISPOSE(Obj)
  wa_BCryptCloseAlgorithmProvider(hAlg,0)
  RETURN Rc

!==============================================================================
NetWebAuthnClass.NewChallenge PROCEDURE()
Rnd    STRING(32)
St     LONG
  CODE
  ! BCRYPT_USE_SYSTEM_PREFERRED_RNG = 2 (hAlgorithm must be NULL)
  St = wa_BCryptGenRandom(0,ADDRESS(Rnd),32,2)
  IF St <> 0 THEN RETURN ''.
  RETURN SELF.Base64UrlEncode(Rnd,32)

!==============================================================================
! raw 91 byte SubjectPublicKeyInfo (as given by getPublicKey()) -> CNG public key handle
NetWebAuthnClass.ImportPublicKey PROCEDURE(STRING pSpki,LONG pSpkiLen,*LONG pKeyHandle,*LONG pAlgHandle)
Blob   STRING(72)
St     LONG
  CODE
  pKeyHandle = 0
  pAlgHandle = 0
  IF pSpkiLen <> 91 THEN RETURN SELF.SetError(WA:Err:BadInput,'public key length').
  IF pSpki[1 : 26] <> SpkiHead OR VAL(pSpki[27]) <> 4 THEN RETURN SELF.SetError(WA:Err:BadInput,'public key is not ES256').
  ! BCRYPT_ECCKEY_BLOB: magic 'ECS1' (ECDSA P-256 public), cbKey = 32, then X and Y
  Blob[1 : 4]   = 'ECS1'
  Blob[5 : 8]   = CHR(32) & CHR(0) & CHR(0) & CHR(0)
  Blob[9 : 40]  = pSpki[28 : 59]
  Blob[41 : 72] = pSpki[60 : 91]
  St = wa_BCryptOpenAlgorithmProvider(ADDRESS(pAlgHandle),ADDRESS(WEcdsaP256),0,0)
  IF St <> 0 THEN RETURN SELF.SetError(WA:Err:Crypto,'BCryptOpenAlgorithmProvider(ECDSA_P256)').
  St = wa_BCryptImportKeyPair(pAlgHandle,0,ADDRESS(WEccPublicBlob),ADDRESS(pKeyHandle),ADDRESS(Blob),72,0)
  IF St <> 0
    wa_BCryptCloseAlgorithmProvider(pAlgHandle,0)
    pAlgHandle = 0
    RETURN SELF.SetError(WA:Err:BadInput,'public key rejected by CNG')
  END
  RETURN WA:Ok

!==============================================================================
! ASN.1 DER ECDSA signature (SEQUENCE{INTEGER r,INTEGER s}) -> 64 bytes r|s as CNG expects
NetWebAuthnClass.DerToRaw PROCEDURE(STRING pDer,LONG pDerLen,*STRING pRaw)
P      LONG
Rl     LONG
Rs     LONG
Part   LONG
  CODE
  pRaw = ALL(CHR(0))
  IF pDerLen < 8 OR VAL(pDer[1]) <> 48 THEN RETURN SELF.SetError(WA:Err:Signature,'signature is not DER').
  P = 2
  IF VAL(pDer[P]) = 129 THEN P += 2 ELSE P += 1.        ! 0x81 = one extra length byte
  LOOP Part = 0 TO 1
    IF P + 1 > pDerLen OR VAL(pDer[P]) <> 2 THEN RETURN SELF.SetError(WA:Err:Signature,'signature layout').
    Rl = VAL(pDer[P + 1])
    Rs = P + 2
    IF Rs + Rl - 1 > pDerLen THEN RETURN SELF.SetError(WA:Err:Signature,'signature layout').
    LOOP WHILE Rl > 32 AND VAL(pDer[Rs]) = 0           ! strip the sign padding byte
      Rs += 1
      Rl -= 1
    END
    IF Rl > 32 OR Rl < 1 THEN RETURN SELF.SetError(WA:Err:Signature,'signature integer size').
    pRaw[Part * 32 + 33 - Rl : Part * 32 + 32] = pDer[Rs : Rs + Rl - 1]
    P = Rs + Rl
  END
  RETURN WA:Ok

!==============================================================================
! clientDataJSON checks: type, challenge, origin
NetWebAuthnClass.CheckClientData PROCEDURE(STRING pType,STRING pChallenge,STRING pClientData)
  CODE
  IF CLIP(SELF.Origin) = '' THEN RETURN SELF.SetError(WA:Err:ClientData,'expected origin not configured').
  IF SELF.JsonField(pClientData,'type') <> CLIP(pType) THEN RETURN SELF.SetError(WA:Err:ClientData,'clientData type').
  IF CLIP(pChallenge) = '' OR SELF.JsonField(pClientData,'challenge') <> CLIP(pChallenge)
    RETURN SELF.SetError(WA:Err:ClientData,'challenge does not match')
  END
  IF SELF.JsonField(pClientData,'origin') <> CLIP(SELF.Origin)
    RETURN SELF.SetError(WA:Err:ClientData,'origin does not match: ' & SELF.JsonField(pClientData,'origin'))
  END
  RETURN WA:Ok

!==============================================================================
! authenticatorData: rpIdHash(32) flags(1) signCount(4) [attested data]
NetWebAuthnClass.CheckAuthData PROCEDURE(STRING pAuthData,LONG pAuthLen,*REAL pSignCount)
Hash   STRING(32)
Flags  LONG
  CODE
  IF pAuthLen < 37 THEN RETURN SELF.SetError(WA:Err:BadInput,'authenticatorData too short').
  IF SELF.Sha256(CLIP(SELF.RpId),LEN(CLIP(SELF.RpId)),Hash) <> WA:Ok THEN RETURN SELF.LastError.
  IF pAuthData[1 : 32] <> Hash THEN RETURN SELF.SetError(WA:Err:RpIdHash,'rpIdHash does not match ' & SELF.RpId).
  Flags = VAL(pAuthData[33])
  IF BAND(Flags,1) = 0 THEN RETURN SELF.SetError(WA:Err:Flags,'user presence missing').
  IF SELF.RequireUV AND BAND(Flags,4) = 0 THEN RETURN SELF.SetError(WA:Err:Flags,'user verification missing').
  pSignCount = ((VAL(pAuthData[34]) * 256 + VAL(pAuthData[35])) * 256 + VAL(pAuthData[36])) * 256 + VAL(pAuthData[37])
  RETURN WA:Ok

!==============================================================================
! options sent to the browser
!==============================================================================
NetWebAuthnClass.LoginOptions PROCEDURE(STRING pChallenge)
  CODE
  RETURN '{"ok":1,"challenge":' & SELF.JsonString(pChallenge) & ',"rpId":' & SELF.JsonString(SELF.RpId) & '}'

!==============================================================================
NetWebAuthnClass.RegistrationOptions PROCEDURE(STRING pChallenge,STRING pUserKey)
UserId STRING(32)
  CODE
  ! the user handle must be opaque: use the SHA-256 of the user key, never the user key itself
  IF SELF.Sha256(CLIP(pUserKey),LEN(CLIP(pUserKey)),UserId) <> WA:Ok THEN RETURN '{"ok":0,"err":"crypto"}'.
  RETURN '{"ok":1,"challenge":' & SELF.JsonString(pChallenge) & |
         ',"rpId":'    & SELF.JsonString(SELF.RpId) & |
         ',"rpName":'  & SELF.JsonString(SELF.RpName) & |
         ',"userId":'  & SELF.JsonString(SELF.Base64UrlEncode(UserId,32)) & |
         ',"userName":' & SELF.JsonString(pUserKey) & |
         ',"excl":['   & SELF.ListCredentialIds(pUserKey) & ']}'

!==============================================================================
! credential store
!==============================================================================
NetWebAuthnClass.OpenStore PROCEDURE()
  CODE
  IF CLIP(SELF.FileName) = '' THEN RETURN SELF.SetError(WA:Err:Store,'credential file not configured').
  WAFileName = CLIP(SELF.FileName)
  OPEN(WACred,42h)
  IF ERRORCODE() = 2 OR ERRORCODE() = 3                ! file / path not found: create it
    CREATE(WACred)
    IF ERRORCODE() THEN RETURN SELF.SetError(WA:Err:Store,'cannot create ' & CLIP(SELF.FileName) & ': ' & ERROR()).
    OPEN(WACred,42h)
  END
  IF ERRORCODE() THEN RETURN SELF.SetError(WA:Err:Store,'cannot open ' & CLIP(SELF.FileName) & ': ' & ERROR()).
  RETURN WA:Ok

!==============================================================================
NetWebAuthnClass.CloseStore PROCEDURE()
  CODE
  CLOSE(WACred)
  RETURN

!==============================================================================
NetWebAuthnClass.ListCredentialIds PROCEDURE(STRING pUserKey)
Out    STRING(WA:MaxStr)
O      LONG
Id     STRING(300)
  CODE
  IF SELF.OpenStore() <> WA:Ok THEN RETURN ''.
  WAC:UserKey = pUserKey
  SET(WAC:ByUser,WAC:ByUser)
  LOOP
    NEXT(WACred)
    IF ERRORCODE() THEN BREAK.
    IF WAC:UserKey <> pUserKey THEN BREAK.
    Id = SELF.JsonString(CLIP(WAC:CredId))
    IF O + LEN(CLIP(Id)) + 2 > WA:MaxStr THEN BREAK.
    IF O > 0
      O += 1
      Out[O] = ','
    END
    Out[O + 1 : O + LEN(CLIP(Id))] = CLIP(Id)
    O += LEN(CLIP(Id))
  END
  SELF.CloseStore()
  IF O = 0 THEN RETURN ''.
  RETURN Out[1 : O]

!==============================================================================
NetWebAuthnClass.CountCredentials PROCEDURE(STRING pUserKey)
N      LONG
  CODE
  IF SELF.OpenStore() <> WA:Ok THEN RETURN 0.
  WAC:UserKey = pUserKey
  SET(WAC:ByUser,WAC:ByUser)
  LOOP
    NEXT(WACred)
    IF ERRORCODE() OR WAC:UserKey <> pUserKey THEN BREAK.
    N += 1
  END
  SELF.CloseStore()
  RETURN N

!==============================================================================
NetWebAuthnClass.DeleteCredentials PROCEDURE(STRING pUserKey)
  CODE
  IF SELF.OpenStore() <> WA:Ok THEN RETURN.
  LOOP
    WAC:UserKey = pUserKey
    SET(WAC:ByUser,WAC:ByUser)
    NEXT(WACred)
    IF ERRORCODE() OR WAC:UserKey <> pUserKey THEN BREAK.
    DELETE(WACred)
    IF ERRORCODE() THEN BREAK.
  END
  SELF.CloseStore()
  RETURN

!==============================================================================
! registration: browser sends credential id, clientDataJSON, authenticatorData and the
! SubjectPublicKeyInfo (getPublicKey()) - all base64url. attestation is 'none', nothing to check there.
!==============================================================================
NetWebAuthnClass.VerifyRegistration PROCEDURE(STRING pChallenge,STRING pCredId,STRING pClientData,STRING pAuthData,STRING pPublicKey,STRING pUserKey,STRING pDevice)
Cdj      STRING(WA:MaxStr)
CdjLen   LONG
Ad       STRING(WA:MaxStr)
AdLen    LONG
Pk       STRING(256)
PkLen    LONG
CredRaw  STRING(1100)
CredLen  LONG
IdLen    LONG
SignCnt  REAL
hKey     LONG
hAlg     LONG
Rc       LONG
  CODE
  SELF.SetError(WA:Ok,'')
  IF CLIP(pUserKey) = '' OR CLIP(pCredId) = '' THEN RETURN SELF.SetError(WA:Err:BadInput,'missing user or credential id').
  CdjLen = SELF.Base64UrlDecode(pClientData,Cdj)
  AdLen  = SELF.Base64UrlDecode(pAuthData,Ad)
  PkLen  = SELF.Base64UrlDecode(pPublicKey,Pk)
  CredLen = SELF.Base64UrlDecode(pCredId,CredRaw)
  IF CdjLen = 0 OR AdLen = 0 OR PkLen = 0 OR CredLen = 0 THEN RETURN SELF.SetError(WA:Err:BadInput,'bad base64').
  Rc = SELF.CheckClientData('webauthn.create',pChallenge,Cdj[1 : CdjLen])
  IF Rc <> WA:Ok THEN RETURN Rc.
  Rc = SELF.CheckAuthData(Ad[1 : AdLen],AdLen,SignCnt)
  IF Rc <> WA:Ok THEN RETURN Rc.
  ! attested credential data present: its credential id must be the one the browser reported
  IF BAND(VAL(Ad[33]),64) = 0 OR AdLen < 55 THEN RETURN SELF.SetError(WA:Err:BadInput,'no attested credential data').
  IdLen = VAL(Ad[54]) * 256 + VAL(Ad[55])
  IF IdLen <> CredLen OR AdLen < 55 + IdLen OR Ad[56 : 55 + IdLen] <> CredRaw[1 : CredLen]
    RETURN SELF.SetError(WA:Err:BadInput,'credential id mismatch')
  END
  Rc = SELF.ImportPublicKey(Pk[1 : PkLen],PkLen,hKey,hAlg)    ! proves the key is a valid P-256 point
  IF Rc <> WA:Ok THEN RETURN Rc.
  wa_BCryptDestroyKey(hKey)
  wa_BCryptCloseAlgorithmProvider(hAlg,0)

  IF SELF.OpenStore() <> WA:Ok THEN RETURN SELF.LastError.
  WAC:CredId = pCredId
  GET(WACred,WAC:ByCred)
  IF ERRORCODE()
    CLEAR(WAC:Record)
    WAC:CredId      = pCredId
    WAC:UserKey     = pUserKey
    WAC:PublicKey   = pPublicKey
    WAC:SignCount   = SignCnt
    WAC:Device      = pDevice
    WAC:Created     = TODAY()
    WAC:CreatedTime = CLOCK()
    ADD(WACred)
  ELSE
    WAC:UserKey   = pUserKey                              ! re-enrolling the same authenticator
    WAC:PublicKey = pPublicKey
    WAC:SignCount = SignCnt
    WAC:Device    = pDevice
    PUT(WACred)
  END
  IF ERRORCODE() THEN Rc = SELF.SetError(WA:Err:Store,'cannot save credential: ' & ERROR()).
  SELF.CloseStore()
  RETURN Rc

!==============================================================================
! login: look the credential up, verify the signature over authData | SHA256(clientDataJSON)
!==============================================================================
NetWebAuthnClass.VerifyAssertion PROCEDURE(STRING pChallenge,STRING pCredId,STRING pClientData,STRING pAuthData,STRING pSignature,*STRING pUserKey)
Cdj      STRING(WA:MaxStr)
CdjLen   LONG
Ad       STRING(WA:MaxStr)
AdLen    LONG
Sig      STRING(256)
SigLen   LONG
Pk       STRING(256)
PkLen    LONG
Raw      STRING(64)
CdjHash  STRING(32)
Msg      STRING(WA:MaxStr + 64)
MsgHash  STRING(32)
SignCnt  REAL
OldCnt   REAL
hKey     LONG
hAlg     LONG
St       LONG
Rc       LONG
  CODE
  SELF.SetError(WA:Ok,'')
  IF CLIP(pCredId) = '' THEN RETURN SELF.SetError(WA:Err:BadInput,'missing credential id').
  CdjLen = SELF.Base64UrlDecode(pClientData,Cdj)
  AdLen  = SELF.Base64UrlDecode(pAuthData,Ad)
  SigLen = SELF.Base64UrlDecode(pSignature,Sig)
  IF CdjLen = 0 OR AdLen = 0 OR SigLen = 0 THEN RETURN SELF.SetError(WA:Err:BadInput,'bad base64').

  Rc = SELF.CheckClientData('webauthn.get',pChallenge,Cdj[1 : CdjLen])
  IF Rc <> WA:Ok THEN RETURN Rc.
  Rc = SELF.CheckAuthData(Ad[1 : AdLen],AdLen,SignCnt)
  IF Rc <> WA:Ok THEN RETURN Rc.

  IF SELF.OpenStore() <> WA:Ok THEN RETURN SELF.LastError.
  WAC:CredId = pCredId
  GET(WACred,WAC:ByCred)
  IF ERRORCODE()
    SELF.CloseStore()
    RETURN SELF.SetError(WA:Err:Unknown,'credential not registered')
  END
  PkLen  = SELF.Base64UrlDecode(WAC:PublicKey,Pk)
  OldCnt = WAC:SignCount
  pUserKey = CLIP(WAC:UserKey)

  Rc = SELF.DerToRaw(Sig[1 : SigLen],SigLen,Raw)
  IF Rc = WA:Ok THEN Rc = SELF.ImportPublicKey(Pk[1 : PkLen],PkLen,hKey,hAlg).
  IF Rc = WA:Ok
    Rc = SELF.Sha256(Cdj[1 : CdjLen],CdjLen,CdjHash)
    IF Rc = WA:Ok
      Msg[1 : AdLen]          = Ad[1 : AdLen]
      Msg[AdLen + 1 : AdLen + 32] = CdjHash
      Rc = SELF.Sha256(Msg[1 : AdLen + 32],AdLen + 32,MsgHash)
    END
    IF Rc = WA:Ok
      St = wa_BCryptVerifySignature(hKey,0,ADDRESS(MsgHash),32,ADDRESS(Raw),64,0)
      IF St <> 0 THEN Rc = SELF.SetError(WA:Err:Signature,'signature does not verify').
    END
    wa_BCryptDestroyKey(hKey)
    wa_BCryptCloseAlgorithmProvider(hAlg,0)
  END

  IF Rc = WA:Ok
    ! counters of 0 mean "not supported" (Apple, most platform passkeys): only enforce when they are used
    IF (SignCnt <> 0 OR OldCnt <> 0) AND SignCnt <= OldCnt
      Rc = SELF.SetError(WA:Err:Counter,'signature counter did not increase')
    ELSE
      WAC:SignCount = SignCnt
      WAC:LastUsed  = TODAY()
      PUT(WACred)
    END
  END
  SELF.CloseStore()
  IF Rc <> WA:Ok THEN pUserKey = ''.
  RETURN Rc
