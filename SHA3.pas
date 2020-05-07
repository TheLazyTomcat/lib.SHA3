{-------------------------------------------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.

-------------------------------------------------------------------------------}
{===============================================================================

  KECCAK-p[b,Nr] is a generalization of KECCAK-f[b] with number of rounds as an
  input parameter.

  b = width of keccak permutation in bits
  f = the generic underlying function for the sponge construction

  Nr = 2L + 12   (number of rounds in keccak permutations)
  L = log2(w)
  w = width of a word (in keccak terminology - size of a sponge lane, in bits),
      in this case 64


  KECCAK[c] = SPONGE[KECCAK-p[1600,24], pad10*1, 1600–c]
  
  SHA3-224(M) = KECCAK[448](M || 01, 224)
  SHA3-256(M) = KECCAK[512](M || 01, 256)
  SHA3-384(M) = KECCAK[768](M || 01, 384)
  SHA3-512(M) = KECCAK[1024](M || 01, 512)

  RawSHAKE128(M, d) = KECCAK[256] (M || 11, d)
  RawSHAKE256(M, d) = KECCAK[512] (M || 11, d)

  SHAKE128(M, d) = RawSHAKE128 (M || 11, d)   SHAKE128(M, d) = KECCAK[256](M || 1111, d)
  SHAKE256(M, d) = RawSHAKE256 (M || 11, d)   SHAKE256(M, d) = KECCAK[512](M || 1111, d)

  d = requested length of a hash, in bits
  M = the input message to a SHA-3 function

  Keccak-f[b]

  b = width of the permutation = 25 (5x5 sponge) * width of keccak word in bits (here 64)

  b = r + c

  r = (bit)rate of sponge function = size of block in bits
  c = capacity of sponge function = size of hash in bits (default is 576)
  
  Keccak[c] (underlying is Keccak-f[1600])


   *TBlockHash --- *TKeccakHash --- TKeccak0Hash
                                 |
                                 |- *TKeccakDefinedHash --- TKeccak224Hash
                                                         |- TKeccak256Hash
                                                         |- TKeccak384Hash
                                                         |- TKeccak512Hash
                                                         |
                                                         |- TKeccak_CHash
                                                         |
                                                         |- *TSHA3Hash --- TSHA3_224Hash
                                                         |              |- TSHA3_256Hash
                                                         |              |- TSHA3_384Hash
                                                         |              |- TSHA3_512Hash
                                                         |
                                                         |- *TSHAKEHash --- TSHAKE128Hash
                                                                         |- TSHAKE256Hash


  SHA3/Keccak hash calculation

  ©František Milt 2018-10-22

  Version 1.1.6

  Following hash variants are supported in current implementation:
    Keccak224
    Keccak256
    Keccak384
    Keccak512
    Keccak[] (in this library marked as Keccak_b)
    SHA3-224
    SHA3-256
    SHA3-384
    SHA3-512
    SHAKE128
    SHAKE256

  Dependencies:
    AuxTypes    - github.com/ncs-sniper/Lib.AuxTypes
    StrRect     - github.com/ncs-sniper/Lib.StrRect
    BitOps      - github.com/ncs-sniper/Lib.BitOps
  * SimpleCPUID - github.com/ncs-sniper/Lib.SimpleCPUID

  SimpleCPUID might not be needed, see BitOps library for details.

===============================================================================}
unit SHA3;

{$IFDEF FPC}
  {$MODE Delphi}
  {$INLINE ON}
  {$DEFINE CanInline}
  {$DEFINE FPC_DisableWarns}
  {$MACRO ON}
{$ELSE}
  {$IF CompilerVersion >= 17 then}  // Delphi 2005+
    {$DEFINE CanInline}
  {$ELSE}
    {$UNDEF CanInline}
  {$IFEND}
{$ENDIF}

interface

uses
  Classes,
  AuxTypes, HashBase;

{===============================================================================
    Common types and constants
===============================================================================}
{
  Bytes in all Keccak and SHA-3 hashes are always ordered from the most
  significant byte to least significant byte (big endian).

  SHA-3 does not differ in little and big endian form, as it is not a single
  quantity, therefore methods like SHA3_*ToLE or SHA3_*ToBE do nothing and are
  present only for the sake of completeness.
}
type
  // fixed length hashes
  TKeccak224 = array[0..27] of UInt8;   PKeccak224 = ^TKeccak224;
  TKeccak256 = array[0..31] of UInt8;   PKeccak256 = ^TKeccak256;
  TKeccak384 = array[0..47] of UInt8;   PKeccak384 = ^TKeccak384;
  TKeccak512 = array[0..64] of UInt8;   PKeccak512 = ^TKeccak512;

  TSHA3_224 = type TKeccak224;    PSHA3_224 = ^TSHA3_224;
  TSHA3_256 = type TKeccak256;    PSHA3_256 = ^TSHA3_256;
  TSHA3_384 = type TKeccak384;    PSHA3_384 = ^TSHA3_384;
  TSHA3_512 = type TKeccak512;    PSHA3_512 = ^TSHA3_512;

  // variable length hashes
  TKeccak_Variable = array of UInt8;  // also used internally as buffer

  TKeccak_c = TKeccak_Variable;   PKeccak_c = ^TKeccak_c; 

  TSHAKE128 = type TKeccak_Variable;    PSHAKE128 = ^TSHAKE128;
  TSHAKE256 = type TKeccak_Variable;    PSHAKE256 = ^TSHAKE256;

  TKeccakFunction = (fnKECCAK0,fnKECCAK224,fnKECCAK256,fnKECCAK384,fnKECCAK512,fnKECCAK_C,
                     fnSHA3_224,fnSHA3_256,fnSHA3_384,fnSHA3_512,fnSHAKE128,fnSHAKE256);

  TKeccak = record
    HashFunction: TKeccakFunction;
    HashBits:     UInt32;
    HashData:     TKeccak_Variable;
  end;

  TSHA3 = TKeccak;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  TKeccakWord = UInt64;

  TKeccakSponge = array[0..4,0..4] of TKeccakWord;

  TKeccakSpongeOverlay = array[0..24] of TKeccakWord; // only used internally  

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

type
  ESHA3Exception = class(EHashException);

  ESHA3IncompatibleClass    = class(ESHA3Exception);
  ESHA3IncompatibleFunction = class(ESHA3Exception);
  ESHA3IncompatibleSize     = class(ESHA3Exception);
  ESHA3ProcessingError      = class(ESHA3Exception);
  ESHA3InvalidBits          = class(ESHA3Exception);

{-------------------------------------------------------------------------------
================================================================================
                                   TKeccakHash                                                                     
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccakHash - class declaration
===============================================================================}
type
  TKeccakHash = class(TBlockHash)
  protected
    fSponge:    TKeccakSponge;
    fHashBits:  UInt32;
    fCapacity:  UInt32;
    procedure SetHashBits(Value: UInt32); virtual;  // must be called before Initialize
    Function GetBitrate: UInt32; virtual;
    class Function HashBufferToLE(HashBuffer: TKeccak_Variable): TKeccak_Variable; virtual;
    class Function HashBufferToBE(HashBuffer: TKeccak_Variable): TKeccak_Variable; virtual;
    class Function HashBufferFromLE(HashBuffer: TKeccak_Variable): TKeccak_Variable; virtual;
    class Function HashBufferFromBE(HashBuffer: TKeccak_Variable): TKeccak_Variable; virtual;
    class Function CapacityFromHashBits(Bits: UInt32): UInt32; virtual;
    class Function PaddingByte: UInt8; virtual;
    Function GetHashBuffer: TKeccak_Variable; virtual;              // override in descendants
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); virtual; // -//-
    procedure Permute; virtual;
    procedure Squeeze; overload; virtual;
    procedure SqueezeInternal(var Buffer; Size: TMemSize); virtual;
    procedure ProcessFirst(const Block); override;
    procedure ProcessBlock(const Block); override;
    procedure ProcessLast; override;
    procedure Initialize; override;
  public
    Function HashSize: TMemSize; reintroduce;
    class Function HashEndianness: THashEndianness; override;
    class Function HashFunction: TKeccakFunction; virtual; abstract;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    procedure Init; override;
    Function Compare(Hash: THashBase): Integer; override;
    Function AsString: String; override;
    procedure FromString(const Str: String); override;
    procedure SaveToStream(Stream: TStream; Endianness: THashEndianness = heDefault); override;
    procedure LoadFromStream(Stream: TStream; Endianness: THashEndianness = heDefault); override;
    property Sponge: TKeccakSponge read fSponge;
    property HashBits: UInt32 read fHashBits;
    property Capacity: UInt32 read fCapacity;
    property Bitrate: UInt32 read GetBitrate;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                  TKeccak0Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak0Hash - class declaration
===============================================================================}
type
  TKeccak0Hash = class(TKeccakHash)
  protected
    procedure Initialize; override;
  public
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    procedure Squeeze(var Buffer; Size: TMemSize); overload; virtual;    
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TKeccakDefinedHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccakDefinedHash - class declaration
===============================================================================}
type
  TKeccakDefinedHash = class(TKeccakHash)
  protected
    procedure SetHashBits(Value: UInt32); override;
    Function GetKeccak: TKeccak; virtual;
  public
    property Keccak: TKeccak read GetKeccak;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak224Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak224Hash - class declaration
===============================================================================}
type
  TKeccak224Hash = class(TKeccakDefinedHash)
  private
    fKeccak224: TKeccak224;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function Keccak224ToLE(Keccak224: TKeccak224): TKeccak224; virtual;
    class Function Keccak224ToBE(Keccak224: TKeccak224): TKeccak224; virtual;
    class Function Keccak224FromLE(Keccak224: TKeccak224): TKeccak224; virtual;
    class Function Keccak224FromBE(Keccak224: TKeccak224): TKeccak224; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TKeccak224); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TKeccak224); reintroduce;
    property Keccak224: TKeccak224 read fKeccak224;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak256Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak256Hash - class declaration
===============================================================================}
type
  TKeccak256Hash = class(TKeccakDefinedHash)
  private
    fKeccak256: TKeccak256;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function Keccak256ToLE(Keccak256: TKeccak256): TKeccak256; virtual;
    class Function Keccak256ToBE(Keccak256: TKeccak256): TKeccak256; virtual;
    class Function Keccak256FromLE(Keccak256: TKeccak256): TKeccak256; virtual;
    class Function Keccak256FromBE(Keccak256: TKeccak256): TKeccak256; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TKeccak256); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TKeccak256); reintroduce;
    property Keccak256: TKeccak256 read fKeccak256;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak384Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak384Hash - class declaration
===============================================================================}
type
  TKeccak384Hash = class(TKeccakDefinedHash)
  private
    fKeccak384: TKeccak384;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function Keccak384ToLE(Keccak384: TKeccak384): TKeccak384; virtual;
    class Function Keccak384ToBE(Keccak384: TKeccak384): TKeccak384; virtual;
    class Function Keccak384FromLE(Keccak384: TKeccak384): TKeccak384; virtual;
    class Function Keccak384FromBE(Keccak384: TKeccak384): TKeccak384; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TKeccak384); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TKeccak384); reintroduce;
    property Keccak384: TKeccak384 read fKeccak384;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak512Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak512Hash - class declaration
===============================================================================}
type
  TKeccak512Hash = class(TKeccakDefinedHash)
  private
    fKeccak512: TKeccak512;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function Keccak512ToLE(Keccak512: TKeccak512): TKeccak512; virtual;
    class Function Keccak512ToBE(Keccak512: TKeccak512): TKeccak512; virtual;
    class Function Keccak512FromLE(Keccak512: TKeccak512): TKeccak512; virtual;
    class Function Keccak512FromBE(Keccak512: TKeccak512): TKeccak512; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TKeccak512); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TKeccak512); reintroduce;
    property Keccak512: TKeccak512 read fKeccak512;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                  TKeccak_CHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak_CHash - class declaration
===============================================================================}
type {$message 'rework - realloc, size change, ...'}
  TKeccak_CHash = class(TKeccakDefinedHash)
  private
    fKeccak_c:  TKeccak_c;
  protected
    procedure SetHashBits(Value: UInt32); override; 
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    Function GetKeccak_c: TKeccak_c; virtual;
    procedure Initialize; override;
  public
    class Function Keccak_cToLE(Keccak_c: TKeccak_c): TKeccak_c; virtual;
    class Function Keccak_cToBE(Keccak_c: TKeccak_c): TKeccak_c; virtual;
    class Function Keccak_cFromLE(Keccak_c: TKeccak_c): TKeccak_c; virtual;
    class Function Keccak_cFromBE(Keccak_c: TKeccak_c): TKeccak_c; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TKeccak_c); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TKeccak_c); reintroduce;
    property HashBits: UInt32 read fHashBits write SetHashBits;
    property Keccak_c: TKeccak_c read GetKeccak_c;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                    TSHA3Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3Hash - class declaration
===============================================================================}
type
  TSHA3Hash = class(TKeccakDefinedHash)
  protected
    class Function CapacityFromHashBits(Bits: UInt32): UInt32; override;
    class Function PaddingByte: UInt8; override;
  public
    property SHA3: TSHA3 read GetKeccak;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_224Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_224Hash - class declaration
===============================================================================}
type
  TSHA3_224Hash = class(TSHA3Hash)
  private
    fSHA3_224: TSHA3_224;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function SHA3_224ToLE(SHA3_224: TSHA3_224): TSHA3_224; virtual;
    class Function SHA3_224ToBE(SHA3_224: TSHA3_224): TSHA3_224; virtual;
    class Function SHA3_224FromLE(SHA3_224: TSHA3_224): TSHA3_224; virtual;
    class Function SHA3_224FromBE(SHA3_224: TSHA3_224): TSHA3_224; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TSHA3); overload; virtual;
    constructor CreateAndInitFrom(Hash: TSHA3_224); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TSHA3_224); reintroduce;
    property SHA3_224: TSHA3_224 read fSHA3_224;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_256Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_256Hash - class declaration
===============================================================================}
type
  TSHA3_256Hash = class(TSHA3Hash)
  private
    fSHA3_256: TSHA3_256;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function SHA3_256ToLE(SHA3_256: TSHA3_256): TSHA3_256; virtual;
    class Function SHA3_256ToBE(SHA3_256: TSHA3_256): TSHA3_256; virtual;
    class Function SHA3_256FromLE(SHA3_256: TSHA3_256): TSHA3_256; virtual;
    class Function SHA3_256FromBE(SHA3_256: TSHA3_256): TSHA3_256; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TSHA3); overload; virtual;
    constructor CreateAndInitFrom(Hash: TSHA3_256); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TSHA3_256); reintroduce;
    property SHA3_256: TSHA3_256 read fSHA3_256;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_384Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_384Hash - class declaration
===============================================================================}
type
  TSHA3_384Hash = class(TSHA3Hash)
  private
    fSHA3_384: TSHA3_384;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function SHA3_384ToLE(SHA3_384: TSHA3_384): TSHA3_384; virtual;
    class Function SHA3_384ToBE(SHA3_384: TSHA3_384): TSHA3_384; virtual;
    class Function SHA3_384FromLE(SHA3_384: TSHA3_384): TSHA3_384; virtual;
    class Function SHA3_384FromBE(SHA3_384: TSHA3_384): TSHA3_384; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TSHA3); overload; virtual;
    constructor CreateAndInitFrom(Hash: TSHA3_384); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TSHA3_384); reintroduce;
    property SHA3_384: TSHA3_384 read fSHA3_384;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_512Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_512Hash - class declaration
===============================================================================}
type
  TSHA3_512Hash = class(TSHA3Hash)
  private
    fSHA3_512: TSHA3_512;
  protected
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function SHA3_512ToLE(SHA3_512: TSHA3_512): TSHA3_512; virtual;
    class Function SHA3_512ToBE(SHA3_512: TSHA3_512): TSHA3_512; virtual;
    class Function SHA3_512FromLE(SHA3_512: TSHA3_512): TSHA3_512; virtual;
    class Function SHA3_512FromBE(SHA3_512: TSHA3_512): TSHA3_512; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TSHA3); overload; virtual;
    constructor CreateAndInitFrom(Hash: TSHA3_512); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TSHA3_512); reintroduce;
    property SHA3_512: TSHA3_512 read fSHA3_512;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                   TSHAKEHash                                   
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHAKEHash - class declaration
===============================================================================}
type
  TSHAKEHash = class(TKeccakDefinedHash)
  protected
    procedure SetHashBits(Value: UInt32); override;
    class Function PaddingByte: UInt8; override;
  end;

{-------------------------------------------------------------------------------
================================================================================
                                  TSHAKE128Hash                                 
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHAKE128Hash - class declaration
===============================================================================}
type
  TSHAKE128Hash = class(TSHAKEHash)
  private
    fSHAKE128:  TSHAKE128;
  protected
    procedure SetHashBits(Value: UInt32); override;
    class Function CapacityFromHashBits(Bits: UInt32): UInt32; override;
    Function GetHashBuffer: TKeccak_Variable; override;
    procedure SetHashBuffer(HashBuffer: TKeccak_Variable); override;
    procedure Initialize; override;
  public
    class Function SHAKE128ToLE(SHAKE128: TSHAKE128): TSHAKE128; virtual;
    class Function SHAKE128ToBE(SHAKE128: TSHAKE128): TSHAKE128; virtual;
    class Function SHAKE128FromLE(SHAKE128: TSHAKE128): TSHAKE128; virtual;
    class Function SHAKE128FromBE(SHAKE128: TSHAKE128): TSHAKE128; virtual;
    class Function HashName: String; override;
    class Function HashFunction: TKeccakFunction; override;
    constructor CreateAndInitFrom(Hash: THashBase); overload; override;
    constructor CreateAndInitFrom(Hash: TKeccak); overload; virtual;
    constructor CreateAndInitFrom(Hash: TSHAKE128); overload; virtual;
    procedure FromStringDef(const Str: String; const Default: TSHAKE128); reintroduce;
    property HashBits: UInt32 read fHashBits write SetHashBits;    
    property SHAKE128: TSHAKE128 read fSHAKE128;
  end;

(*
type
  TKeccakHashSize = (Keccak224,Keccak256,Keccak384,Keccak512,Keccak_b,
                     SHA3_224,SHA3_256,SHA3_384,SHA3_512,SHAKE128,SHAKE256);

  TSHA3HashSize = TKeccakHashSize;

  TKeccakSponge = array[0..4,0..4] of UInt64;  // First index is Y, second X
  
  TKeccakSpongeOverlay = array[0..24] of UInt64;

  TKeccakState = record
    HashSize:   TKeccakHashSize;
    HashBits:   UInt32;
    BlockSize:  UInt32;
    Sponge:     TKeccakSponge;
  end;

  TSHA3State = TKeccakState;

  TKeccakHash = record
    HashSize: TKeccakHashSize;
    HashBits: UInt32;
    HashData: array of UInt8;
  end;

  TSHA3Hash = TKeccakHash;

Function GetBlockSize(HashSize: TSHA3HashSize): UInt32;

Function InitialSHA3State(HashSize: TSHA3HashSize; HashBits: UInt32 = 0): TSHA3State;

Function SHA3ToStr(Hash: TSHA3Hash): String;
Function StrToSHA3(HashSize: TSHA3HashSize; Str: String): TSHA3Hash;
Function TryStrToSHA3(HashSize: TSHA3HashSize;const Str: String; out Hash: TSHA3Hash): Boolean;
Function StrToSHA3Def(HashSize: TSHA3HashSize;const Str: String; Default: TSHA3Hash): TSHA3Hash;

Function CompareSHA3(A,B: TSHA3Hash): Integer;
Function SameSHA3(A,B: TSHA3Hash): Boolean;

Function BinaryCorrectSHA3(Hash: TSHA3Hash): TSHA3Hash;{$IFDEF CanInline} inline; {$ENDIF}

procedure BufferSHA3(var State: TSHA3State; const Buffer; Size: TMemSize); overload;
Function LastBufferSHA3(State: TSHA3State; const Buffer; Size: TMemSize): TSHA3Hash;

Function BufferSHA3(HashSize: TSHA3HashSize; const Buffer; Size: TMemSize; HashBits: UInt32 = 0): TSHA3Hash; overload;

Function AnsiStringSHA3(HashSize: TSHA3HashSize; const Str: AnsiString; HashBits: UInt32 = 0): TSHA3Hash;{$IFDEF CanInline} inline; {$ENDIF}
Function WideStringSHA3(HashSize: TSHA3HashSize; const Str: WideString; HashBits: UInt32 = 0): TSHA3Hash;{$IFDEF CanInline} inline; {$ENDIF}
Function StringSHA3(HashSize: TSHA3HashSize; const Str: String; HashBits: UInt32 = 0): TSHA3Hash;{$IFDEF CanInline} inline; {$ENDIF}

Function StreamSHA3(HashSize: TSHA3HashSize; Stream: TStream; Count: Int64 = -1; HashBits: UInt32 = 0): TSHA3Hash;
Function FileSHA3(HashSize: TSHA3HashSize; const FileName: String; HashBits: UInt32 = 0): TSHA3Hash;

//------------------------------------------------------------------------------

type
  TSHA3Context = type Pointer;

Function SHA3_Init(HashSize: TSHA3HashSize; HashBits: UInt32 = 0): TSHA3Context;
procedure SHA3_Update(Context: TSHA3Context; const Buffer; Size: TMemSize);
Function SHA3_Final(var Context: TSHA3Context; const Buffer; Size: TMemSize): TSHA3Hash; overload;
Function SHA3_Final(var Context: TSHA3Context): TSHA3Hash; overload;
Function SHA3_Hash(HashSize: TSHA3HashSize; const Buffer; Size: TMemSize; HashBits: UInt32 = 0): TSHA3Hash;
*)

implementation

uses
  SysUtils, Math, BitOps, StrRect;

{===============================================================================
    Private auxiliary functions
===============================================================================}

Function EndianSwap(Sponge: TKeccakSponge): TKeccakSponge; overload;
var
  i:  Integer;
begin
For i := Low(TKeccakSpongeOverlay) to High(TKeccakSpongeOverlay) do
  TKeccakSpongeOverlay(Result)[i] := EndianSwap(TKeccakSpongeOverlay(Sponge)[i]);
end;

{-------------------------------------------------------------------------------
================================================================================
                                   TKeccakHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccakHash - calculation constants
===============================================================================}

const
  KECCAK_ROUND_CONSTS: array[0..23] of UInt64 = (
    UInt64($0000000000000001), UInt64($0000000000008082), UInt64($800000000000808A),
    UInt64($8000000080008000), UInt64($000000000000808B), UInt64($0000000080000001),
    UInt64($8000000080008081), UInt64($8000000000008009), UInt64($000000000000008A),
    UInt64($0000000000000088), UInt64($0000000080008009), UInt64($000000008000000A),
    UInt64($000000008000808B), UInt64($800000000000008B), UInt64($8000000000008089),
    UInt64($8000000000008003), UInt64($8000000000008002), UInt64($8000000000000080),
    UInt64($000000000000800A), UInt64($800000008000000A), UInt64($8000000080008081),
    UInt64($8000000000008080), UInt64($0000000080000001), UInt64($8000000080008008));

  KECCAK_ROT_COEFS: array[0..4,0..4] of UInt8 = ( // first index is X, second Y
    {X = 0} ( 0,36, 3,41,18),
    {X = 1} ( 1,44,10,45, 2),
    {X = 2} (62, 6,43,15,61),
    {X = 3} (28,55,25,21,56),
    {X = 4} (27,20,39, 8,14));

  KECCAK_DEFAULT_CAPACITY = 576;

{===============================================================================
    TKeccakHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccakHash - protected methods
-------------------------------------------------------------------------------}

procedure TKeccakHash.SetHashBits(Value: UInt32);
begin
If ((Value mod 8) = 0) and (Value < (25 * 8 * SizeOf(TKeccakWord){1600})) then
  begin
    fHashBits := Value;
    fCapacity := CapacityFromHashBits(fHashBits);
    fBlockSize := Bitrate div 8;
  end
else raise ESHA3InvalidBits.CreateFmt('TKeccakHash.SetHashBits: Invalid hash bits (%d).',[Value]);
end;

//------------------------------------------------------------------------------

Function TKeccakHash.GetBitrate: UInt32;
begin
Result := (25 * 8 * SizeOf(TKeccakWord){1600}) - fCapacity;
end;

//------------------------------------------------------------------------------

class Function TKeccakHash.HashBufferToLE(HashBuffer: TKeccak_Variable): TKeccak_Variable;
begin
Result := HashBuffer;
end;

//------------------------------------------------------------------------------

class Function TKeccakHash.HashBufferToBE(HashBuffer: TKeccak_Variable): TKeccak_Variable;
begin
Result := HashBuffer;
end;
 
//------------------------------------------------------------------------------

class Function TKeccakHash.HashBufferFromLE(HashBuffer: TKeccak_Variable): TKeccak_Variable;
begin
Result := HashBuffer;
end;
 
//------------------------------------------------------------------------------

class Function TKeccakHash.HashBufferFromBE(HashBuffer: TKeccak_Variable): TKeccak_Variable;
begin
Result := HashBuffer;
end;

//------------------------------------------------------------------------------

class Function TKeccakHash.CapacityFromHashBits(Bits: UInt32): UInt32;
begin
If (Bits > 0) and (Bits < (25 * 4 * SizeOf(TKeccakWord){800})) then
  Result := Bits * 2 {$message '?!?'}
else
  Result := KECCAK_DEFAULT_CAPACITY;
end;

//------------------------------------------------------------------------------

class Function TKeccakHash.PaddingByte: UInt8;
begin
Result := $01;  // keccak padding (pad10*1)
end;

//------------------------------------------------------------------------------

Function TKeccakHash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,0);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If Length(HashBuffer) <> 0 then
  raise ESHA3IncompatibleSize.CreateFmt('TKeccakHash.SetHashBuffer: Incompatible hash size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.Permute;
var
  i:    Integer;
  B:    TKeccakSponge;
  C,D:  array[0..4] of TKeccakWord;
begin
// 24 rounds (12 + 2L; where L = log2(64) = 6; 64 is length of sponge word in bits)
For i := 0 to 23 do
  begin
    C[0] := fSponge[0,0] xor fSponge[1,0] xor fSponge[2,0] xor fSponge[3,0] xor fSponge[4,0];
    C[1] := fSponge[0,1] xor fSponge[1,1] xor fSponge[2,1] xor fSponge[3,1] xor fSponge[4,1];
    C[2] := fSponge[0,2] xor fSponge[1,2] xor fSponge[2,2] xor fSponge[3,2] xor fSponge[4,2];
    C[3] := fSponge[0,3] xor fSponge[1,3] xor fSponge[2,3] xor fSponge[3,3] xor fSponge[4,3];
    C[4] := fSponge[0,4] xor fSponge[1,4] xor fSponge[2,4] xor fSponge[3,4] xor fSponge[4,4];

    D[0] := C[4] xor ROL(C[1],1);
    D[1] := C[0] xor ROL(C[2],1);
    D[2] := C[1] xor ROL(C[3],1);
    D[3] := C[2] xor ROL(C[4],1);
    D[4] := C[3] xor ROL(C[0],1);

    fSponge[0,0] := fSponge[0,0] xor D[0];
    fSponge[0,1] := fSponge[0,1] xor D[1];
    fSponge[0,2] := fSponge[0,2] xor D[2];
    fSponge[0,3] := fSponge[0,3] xor D[3];
    fSponge[0,4] := fSponge[0,4] xor D[4];
    fSponge[1,0] := fSponge[1,0] xor D[0];
    fSponge[1,1] := fSponge[1,1] xor D[1];
    fSponge[1,2] := fSponge[1,2] xor D[2];
    fSponge[1,3] := fSponge[1,3] xor D[3];
    fSponge[1,4] := fSponge[1,4] xor D[4];
    fSponge[2,0] := fSponge[2,0] xor D[0];
    fSponge[2,1] := fSponge[2,1] xor D[1];
    fSponge[2,2] := fSponge[2,2] xor D[2];
    fSponge[2,3] := fSponge[2,3] xor D[3];
    fSponge[2,4] := fSponge[2,4] xor D[4];
    fSponge[3,0] := fSponge[3,0] xor D[0];
    fSponge[3,1] := fSponge[3,1] xor D[1];
    fSponge[3,2] := fSponge[3,2] xor D[2];
    fSponge[3,3] := fSponge[3,3] xor D[3];
    fSponge[3,4] := fSponge[3,4] xor D[4];
    fSponge[4,0] := fSponge[4,0] xor D[0];
    fSponge[4,1] := fSponge[4,1] xor D[1];
    fSponge[4,2] := fSponge[4,2] xor D[2];
    fSponge[4,3] := fSponge[4,3] xor D[3];
    fSponge[4,4] := fSponge[4,4] xor D[4];

    B[0,0] := ROL(fSponge[0,0],KECCAK_ROT_COEFS[0,0]);
    B[2,0] := ROL(fSponge[0,1],KECCAK_ROT_COEFS[1,0]);
    B[4,0] := ROL(fSponge[0,2],KECCAK_ROT_COEFS[2,0]);
    B[1,0] := ROL(fSponge[0,3],KECCAK_ROT_COEFS[3,0]);
    B[3,0] := ROL(fSponge[0,4],KECCAK_ROT_COEFS[4,0]);
    B[3,1] := ROL(fSponge[1,0],KECCAK_ROT_COEFS[0,1]);
    B[0,1] := ROL(fSponge[1,1],KECCAK_ROT_COEFS[1,1]);
    B[2,1] := ROL(fSponge[1,2],KECCAK_ROT_COEFS[2,1]);
    B[4,1] := ROL(fSponge[1,3],KECCAK_ROT_COEFS[3,1]);
    B[1,1] := ROL(fSponge[1,4],KECCAK_ROT_COEFS[4,1]);
    B[1,2] := ROL(fSponge[2,0],KECCAK_ROT_COEFS[0,2]);
    B[3,2] := ROL(fSponge[2,1],KECCAK_ROT_COEFS[1,2]);
    B[0,2] := ROL(fSponge[2,2],KECCAK_ROT_COEFS[2,2]);
    B[2,2] := ROL(fSponge[2,3],KECCAK_ROT_COEFS[3,2]);
    B[4,2] := ROL(fSponge[2,4],KECCAK_ROT_COEFS[4,2]);
    B[4,3] := ROL(fSponge[3,0],KECCAK_ROT_COEFS[0,3]);
    B[1,3] := ROL(fSponge[3,1],KECCAK_ROT_COEFS[1,3]);
    B[3,3] := ROL(fSponge[3,2],KECCAK_ROT_COEFS[2,3]);
    B[0,3] := ROL(fSponge[3,3],KECCAK_ROT_COEFS[3,3]);
    B[2,3] := ROL(fSponge[3,4],KECCAK_ROT_COEFS[4,3]);
    B[2,4] := ROL(fSponge[4,0],KECCAK_ROT_COEFS[0,4]);
    B[4,4] := ROL(fSponge[4,1],KECCAK_ROT_COEFS[1,4]);
    B[1,4] := ROL(fSponge[4,2],KECCAK_ROT_COEFS[2,4]);
    B[3,4] := ROL(fSponge[4,3],KECCAK_ROT_COEFS[3,4]);
    B[0,4] := ROL(fSponge[4,4],KECCAK_ROT_COEFS[4,4]);

    fSponge[0,0] := B[0,0] xor ((not B[0,1]) and B[0,2]);
    fSponge[0,1] := B[0,1] xor ((not B[0,2]) and B[0,3]);
    fSponge[0,2] := B[0,2] xor ((not B[0,3]) and B[0,4]);
    fSponge[0,3] := B[0,3] xor ((not B[0,4]) and B[0,0]);
    fSponge[0,4] := B[0,4] xor ((not B[0,0]) and B[0,1]);
    fSponge[1,0] := B[1,0] xor ((not B[1,1]) and B[1,2]);
    fSponge[1,1] := B[1,1] xor ((not B[1,2]) and B[1,3]);
    fSponge[1,2] := B[1,2] xor ((not B[1,3]) and B[1,4]);
    fSponge[1,3] := B[1,3] xor ((not B[1,4]) and B[1,0]);
    fSponge[1,4] := B[1,4] xor ((not B[1,0]) and B[1,1]);
    fSponge[2,0] := B[2,0] xor ((not B[2,1]) and B[2,2]);
    fSponge[2,1] := B[2,1] xor ((not B[2,2]) and B[2,3]);
    fSponge[2,2] := B[2,2] xor ((not B[2,3]) and B[2,4]);
    fSponge[2,3] := B[2,3] xor ((not B[2,4]) and B[2,0]);
    fSponge[2,4] := B[2,4] xor ((not B[2,0]) and B[2,1]);
    fSponge[3,0] := B[3,0] xor ((not B[3,1]) and B[3,2]);
    fSponge[3,1] := B[3,1] xor ((not B[3,2]) and B[3,3]);
    fSponge[3,2] := B[3,2] xor ((not B[3,3]) and B[3,4]);
    fSponge[3,3] := B[3,3] xor ((not B[3,4]) and B[3,0]);
    fSponge[3,4] := B[3,4] xor ((not B[3,0]) and B[3,1]);
    fSponge[4,0] := B[4,0] xor ((not B[4,1]) and B[4,2]);
    fSponge[4,1] := B[4,1] xor ((not B[4,2]) and B[4,3]);
    fSponge[4,2] := B[4,2] xor ((not B[4,3]) and B[4,4]);
    fSponge[4,3] := B[4,3] xor ((not B[4,4]) and B[4,0]);
    fSponge[4,4] := B[4,4] xor ((not B[4,0]) and B[4,1]);

    fSponge[0,0] := fSponge[0,0] xor KECCAK_ROUND_CONSTS[i];
  end;
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.Squeeze;
var
  Temp: TKeccak_Variable;
begin
If HashSize > 0 then
  begin
    SetLength(Temp,HashSize);
    SqueezeInternal(Temp[0],HashSize);
    SetHashBuffer(Temp);
  end;
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.SqueezeInternal(var Buffer; Size: TMemSize);

  procedure SqueezeSponge(var Dest; Count: TMemSize);
  {$IFDEF ENDIAN_BIG}
  var
    Temp: TKeccakSponge;
    i:    Integer;
  {$ENDIF}
  begin
  {$IFDEF ENDIAN_BIG}
    Temp := EndianSwap(fSponge);
    Move(Temp,Dest,Count);
  {$ELSE}
    Move(fSponge,Dest,Count);
  {$ENDIF}
  end;
  
begin
If Size > 0 then
  begin
    If Size > fBlockSize then
      while Size > 0 do
        begin
          SqueezeSponge(Pointer(PtrUInt(@Buffer) + PtrUInt(HashSize) - PtrUInt(Size))^,Min(Size,fBlockSize));
          Dec(Size,Min(Size,fBlockSize));
          Permute;
        end
    else SqueezeSponge(Buffer,Size);
  end;
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.ProcessFirst(const Block);
begin
inherited;
ProcessBlock(Block);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.ProcessBlock(const Block);
var
  i:    Integer;
  Buff: TKeccakSpongeOverlay absolute Block;
begin
For i := 0 to Pred(fBlockSize div 8) do
  TKeccakSpongeOverlay(fSponge)[i] := TKeccakSpongeOverlay(fSponge)[i] xor
    {$IFDEF ENDIAN_BIG}EndianSwap{$ENDIF}(Buff[i]);
Permute;
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.ProcessLast;
begin
If fTempCount < fBlockSize then
  begin
    // padding can fit
  //{$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
    FillChar(Pointer(PtrUInt(fTempBlock) + PtrUInt(fTempCount))^,fBlockSize - fTempCount,0);
    PUInt8(PtrUInt(fTempBlock) + PtrUInt(fTempCount))^ := PaddingByte;
    PUInt8(PtrUInt(fTempBlock) + PtrUInt(fBlockSize) - 1)^ :=
      PUInt8(PtrUInt(fTempBlock) + PtrUInt(fBlockSize) - 1)^ or $80;
  //{$IFDEF FPCDWM}{$POP}{$ENDIF}
    ProcessBlock(fTempBlock^);
    Squeeze;
  end
else
  begin
    // padding cannot fit
    If fTempCount = fBlockSize then
      begin
        ProcessBlock(fTempBlock^);
      //{$IFDEF FPCDWM}{$PUSH}W4055{$ENDIF}
        FillChar(fTempBlock^,fBlockSize,0);
        PUInt8(fTempBlock)^ := PaddingByte;
        PUInt8(PtrUInt(fTempBlock) + PtrUInt(fBlockSize) - 1)^ := $80;
      //{$IFDEF FPCDWM}{$POP}{$ENDIF}
        ProcessBlock(fTempBlock^);
        Squeeze;
      end
    else raise ESHA3ProcessingError.CreateFmt('TKeccakHash.ProcessLast: Invalid data transfer (%d).',[fTempCount]);
  end;
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.Initialize;
begin
inherited;
FillChar(fSponge,SizeOf(TKeccakSponge),0);
end;

{-------------------------------------------------------------------------------
    TKeccakHash - public methods
-------------------------------------------------------------------------------}

Function TKeccakHash.HashSize: TMemSize;
begin
Result := fHashBits div 8;
end;

//------------------------------------------------------------------------------

class Function TKeccakHash.HashEndianness: THashEndianness;
begin
Result := heBig;
end;

//------------------------------------------------------------------------------

constructor TKeccakHash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccakHash then
  begin
    fSponge := TKeccakHash(Hash).Sponge;
    fHashBits := TKeccakHash(Hash).HashBits;
    fCapacity := TKeccakHash(Hash).Capacity;
  end
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccakHash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.Init;
begin
inherited;
FillChar(fSponge,SizeOf(TKeccakSponge),0);
end;

//------------------------------------------------------------------------------

Function TKeccakHash.Compare(Hash: THashBase): Integer;
var
  A,B:  TKeccak_Variable;
  i:    Integer;
begin
If Hash is Self.ClassType then
  begin
    Result := 0;
    A := GetHashBuffer;
    B := TKeccakHash(Hash).GetHashBuffer;
    If Length(A) = Length(B) then
      begin
        For i := Low(A) to High(A) do
          If A[i] > B[i] then
            begin
              Result := +1;
              Break;
            end
          else If A[i] < B[i] then
            begin
              Result := -1;
              Break;
            end;
      end
    else raise ESHA3IncompatibleSize.CreateFmt('TKeccakHash.Compare: Incompatible size (%d,%d).',[Length(A),Length(B)]);
  end
else raise ESHA3IncompatibleClass.CreateFmt('TKeccakHash.Compare: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

Function TKeccakHash.AsString: String;
var
  Temp: TKeccak_Variable;
  i:    Integer;
begin
Temp := GetHashBuffer;
If Length(Temp) > 0 then
  begin
    Result := StringOfChar('0',Length(Temp) * 2);
    For i := Low(Temp) to High(Temp) do
      begin
        Result[(i * 2) + 2] := IntToHex(Temp[i] and $0F,1)[1];
        Result[(i * 2) + 1] := IntToHex(Temp[i] shr 4,1)[1];
      end;
  end
else Result := '';
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.FromString(const Str: String);
var
  TempStr:  String;
  i:        Integer;
  Temp:     TKeccak_Variable;
begin
If Length(Str) < Integer(HashSize * 2) then
  TempStr := StringOfChar('0',Integer(HashSize * 2) - Length(Str)) + Str
else If Length(Str) > Integer(HashSize * 2) then
  TempStr := Copy(Str,Length(Str) - Pred(Integer(HashSize * 2)),Integer(HashSize * 2))
else
  TempStr := Str;
SetLength(Temp,HashSize);
For i := Low(Temp) to High(Temp) do
  Temp[i] := UInt8(StrToInt('$' + Copy(TempStr,(i * 2) + 1,2)));
SetHashBuffer(Temp);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.SaveToStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TKeccak_Variable;
begin
case Endianness of
  heSystem: Temp := {$IFDEF ENDIAN_BIG}HashBufferToBE{$ELSE}HashBufferToLE{$ENDIF}(GetHashBuffer);
  heLittle: Temp := HashBufferToLE(GetHashBuffer);
  heBig:    Temp := HashBufferToBE(GetHashBuffer);
else
 {heDefault}
  Temp := GetHashBuffer;
end;
If Length(Temp) > 0 then
  Stream.WriteBuffer(Temp[0],HashSize);
end;

//------------------------------------------------------------------------------

procedure TKeccakHash.LoadFromStream(Stream: TStream; Endianness: THashEndianness = heDefault);
var
  Temp: TKeccak_Variable;
begin
SetLength(Temp,HashSize);
If Length(Temp) > 0 then
  begin
    Stream.ReadBuffer(Temp[0],HashSize);
    case Endianness of
      heSystem: SetHashBuffer({$IFDEF ENDIAN_BIG}HashBufferFromBE{$ELSE}HashBufferFromLE{$ENDIF}(Temp));
      heLittle: SetHashBuffer(HashBufferFromLE(Temp));
      heBig:    SetHashBuffer(HashBufferFromBE(Temp));
    else
     {heDefault}
      SetHashBuffer(Temp);
    end;
  end;
end;


{-------------------------------------------------------------------------------
================================================================================
                                  TKeccak0Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak0Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak0Hash - protected methods
-------------------------------------------------------------------------------}

procedure TKeccak0Hash.Initialize;
begin
SetHashBits(0);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak0Hash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak0Hash.HashName: String;
begin
Result := 'Keccak[]';
end;

//------------------------------------------------------------------------------

class Function TKeccak0Hash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK0;
end;

//------------------------------------------------------------------------------

procedure TKeccak0Hash.Squeeze(var Buffer; Size: TMemSize);
begin
SqueezeInternal(Buffer,Size);
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TKeccakDefinedHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccakDefinedHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccakDefinedHash - public methods
-------------------------------------------------------------------------------}

procedure TKeccakDefinedHash.SetHashBits(Value: UInt32);
begin
If Value > 0 then
  inherited SetHashBits(Value)
else
  raise ESHA3InvalidBits.CreateFmt('TKeccakDefinedHash.SetHashBits: Invalid hash bits (%d).',[Value]);
end;

//------------------------------------------------------------------------------

Function TKeccakDefinedHash.GetKeccak: TKeccak;
begin
Result.HashFunction := HashFunction;
Result.HashBits := fHashBits;
If Result.HashBits <> 0 then
  Result.HashData := Copy(GetHashBuffer)
else
  SetLength(Result.HashData,0);
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak224Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak224Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak224Hash - protected methods
-------------------------------------------------------------------------------}

Function TKeccak224Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fKeccak224,Result[0],HashSize);
end;

//------------------------------------------------------------------------------

procedure TKeccak224Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fKeccak224,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TKeccak224Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

procedure TKeccak224Hash.Initialize;
begin
SetHashBits(224);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak224Hash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak224Hash.Keccak224ToLE(Keccak224: TKeccak224): TKeccak224;
begin
Result := Keccak224;
end;

//------------------------------------------------------------------------------

class Function TKeccak224Hash.Keccak224ToBE(Keccak224: TKeccak224): TKeccak224;
begin
Result := Keccak224;
end;

//------------------------------------------------------------------------------

class Function TKeccak224Hash.Keccak224FromLE(Keccak224: TKeccak224): TKeccak224;
begin
Result := Keccak224;
end;

//------------------------------------------------------------------------------

class Function TKeccak224Hash.Keccak224FromBE(Keccak224: TKeccak224): TKeccak224;
begin
Result := Keccak224;
end;

//------------------------------------------------------------------------------

class Function TKeccak224Hash.HashName: String;
begin
Result := 'Keccak[224]';
end;

//------------------------------------------------------------------------------

class Function TKeccak224Hash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK224;
end;

//------------------------------------------------------------------------------

constructor TKeccak224Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccak224Hash then
  fKeccak224 := TKeccak224Hash(Hash).Keccak224
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccak224Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

constructor TKeccak224Hash.CreateAndInitFrom(Hash: TKeccak);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then  // this implies equal hash bits
      Move(Hash.HashData[0],fKeccak224,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TKeccak224Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TKeccak224Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
  
//------------------------------------------------------------------------------

constructor TKeccak224Hash.CreateAndInitFrom(Hash: TKeccak224);
begin
CreateAndInit;
fKeccak224 := Hash;
end;

//------------------------------------------------------------------------------

procedure TKeccak224Hash.FromStringDef(const Str: String; const Default: TKeccak224);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fKeccak224 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak256Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak256Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak256Hash - protected methods
-------------------------------------------------------------------------------}

Function TKeccak256Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fKeccak256,Result[0],HashSize);
end;

//------------------------------------------------------------------------------

procedure TKeccak256Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fKeccak256,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TKeccak256Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

procedure TKeccak256Hash.Initialize;
begin
SetHashBits(256);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak256Hash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak256Hash.Keccak256ToLE(Keccak256: TKeccak256): TKeccak256;
begin
Result := Keccak256;
end;

//------------------------------------------------------------------------------

class Function TKeccak256Hash.Keccak256ToBE(Keccak256: TKeccak256): TKeccak256;
begin
Result := Keccak256;
end;

//------------------------------------------------------------------------------

class Function TKeccak256Hash.Keccak256FromLE(Keccak256: TKeccak256): TKeccak256;
begin
Result := Keccak256;
end;

//------------------------------------------------------------------------------

class Function TKeccak256Hash.Keccak256FromBE(Keccak256: TKeccak256): TKeccak256;
begin
Result := Keccak256;
end;

//------------------------------------------------------------------------------

class Function TKeccak256Hash.HashName: String;
begin
Result := 'Keccak[256]';
end;

//------------------------------------------------------------------------------

class Function TKeccak256Hash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK256;
end;

//------------------------------------------------------------------------------

constructor TKeccak256Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccak256Hash then
  fKeccak256 := TKeccak256Hash(Hash).Keccak256
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccak256Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

constructor TKeccak256Hash.CreateAndInitFrom(Hash: TKeccak);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then 
      Move(Hash.HashData[0],fKeccak256,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TKeccak256Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TKeccak256Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
  
//------------------------------------------------------------------------------

constructor TKeccak256Hash.CreateAndInitFrom(Hash: TKeccak256);
begin
CreateAndInit;
fKeccak256 := Hash;
end;

//------------------------------------------------------------------------------

procedure TKeccak256Hash.FromStringDef(const Str: String; const Default: TKeccak256);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fKeccak256 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak384Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak384Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak384Hash - protected methods
-------------------------------------------------------------------------------}

Function TKeccak384Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fKeccak384,Result[0],HashSize);
end;

//------------------------------------------------------------------------------

procedure TKeccak384Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fKeccak384,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TKeccak384Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

procedure TKeccak384Hash.Initialize;
begin
SetHashBits(384);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak384Hash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak384Hash.Keccak384ToLE(Keccak384: TKeccak384): TKeccak384;
begin
Result := Keccak384;
end;

//------------------------------------------------------------------------------

class Function TKeccak384Hash.Keccak384ToBE(Keccak384: TKeccak384): TKeccak384;
begin
Result := Keccak384;
end;

//------------------------------------------------------------------------------

class Function TKeccak384Hash.Keccak384FromLE(Keccak384: TKeccak384): TKeccak384;
begin
Result := Keccak384;
end;

//------------------------------------------------------------------------------

class Function TKeccak384Hash.Keccak384FromBE(Keccak384: TKeccak384): TKeccak384;
begin
Result := Keccak384;
end;

//------------------------------------------------------------------------------

class Function TKeccak384Hash.HashName: String;
begin
Result := 'Keccak[384]';
end;

//------------------------------------------------------------------------------

class Function TKeccak384Hash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK384;
end;

//------------------------------------------------------------------------------

constructor TKeccak384Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccak384Hash then
  fKeccak384 := TKeccak384Hash(Hash).Keccak384
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccak384Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

constructor TKeccak384Hash.CreateAndInitFrom(Hash: TKeccak);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then 
      Move(Hash.HashData[0],fKeccak384,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TKeccak384Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TKeccak384Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
  
//------------------------------------------------------------------------------

constructor TKeccak384Hash.CreateAndInitFrom(Hash: TKeccak384);
begin
CreateAndInit;
fKeccak384 := Hash;
end;

//------------------------------------------------------------------------------

procedure TKeccak384Hash.FromStringDef(const Str: String; const Default: TKeccak384);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fKeccak384 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TKeccak512Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak512Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak512Hash - protected methods
-------------------------------------------------------------------------------}

Function TKeccak512Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fKeccak512,Result[0],HashSize);
end;

//------------------------------------------------------------------------------

procedure TKeccak512Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fKeccak512,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TKeccak512Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

procedure TKeccak512Hash.Initialize;
begin
SetHashBits(512);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak512Hash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak512Hash.Keccak512ToLE(Keccak512: TKeccak512): TKeccak512;
begin
Result := Keccak512;
end;

//------------------------------------------------------------------------------

class Function TKeccak512Hash.Keccak512ToBE(Keccak512: TKeccak512): TKeccak512;
begin
Result := Keccak512;
end;

//------------------------------------------------------------------------------

class Function TKeccak512Hash.Keccak512FromLE(Keccak512: TKeccak512): TKeccak512;
begin
Result := Keccak512;
end;

//------------------------------------------------------------------------------

class Function TKeccak512Hash.Keccak512FromBE(Keccak512: TKeccak512): TKeccak512;
begin
Result := Keccak512;
end;

//------------------------------------------------------------------------------

class Function TKeccak512Hash.HashName: String;
begin
Result := 'Keccak[512]';
end;

//------------------------------------------------------------------------------

class Function TKeccak512Hash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK512;
end;

//------------------------------------------------------------------------------

constructor TKeccak512Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccak512Hash then
  fKeccak512 := TKeccak512Hash(Hash).Keccak512
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccak512Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;

//------------------------------------------------------------------------------

constructor TKeccak512Hash.CreateAndInitFrom(Hash: TKeccak);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then 
      Move(Hash.HashData[0],fKeccak512,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TKeccak512Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TKeccak512Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
  
//------------------------------------------------------------------------------

constructor TKeccak512Hash.CreateAndInitFrom(Hash: TKeccak512);
begin
CreateAndInit;
fKeccak512 := Hash;
end;

//------------------------------------------------------------------------------

procedure TKeccak512Hash.FromStringDef(const Str: String; const Default: TKeccak512);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fKeccak512 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                  TKeccak_CHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TKeccak_CHash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TKeccak_CHash - protected methods
-------------------------------------------------------------------------------}

procedure TKeccak_CHash.SetHashBits(Value: UInt32);
begin
inherited SetHashBits(Value);
ReallocMem(fTempBlock,fBlockSize);
end;

//------------------------------------------------------------------------------

Function TKeccak_CHash.GetHashBuffer: TKeccak_Variable;
begin
Result := Copy(fKeccak_c);
end;

//------------------------------------------------------------------------------

procedure TKeccak_CHash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  fKeccak_c := Copy(HashBuffer)
else
  raise ESHA3IncompatibleSize.CreateFmt('TKeccak_CHash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;

//------------------------------------------------------------------------------

Function TKeccak_CHash.GetKeccak_c: TKeccak_c;
begin
Result := Copy(fKeccak_c);
end;

//------------------------------------------------------------------------------

procedure TKeccak_CHash.Initialize;
begin
SetHashBits(KECCAK_DEFAULT_CAPACITY);
inherited;
end;

{-------------------------------------------------------------------------------
    TKeccak_CHash - public methods
-------------------------------------------------------------------------------}

class Function TKeccak_CHash.Keccak_cToLE(Keccak_c: TKeccak_c): TKeccak_c;
begin
Result := Copy(Keccak_c);
end;
  
//------------------------------------------------------------------------------

class Function TKeccak_CHash.Keccak_cToBE(Keccak_c: TKeccak_c): TKeccak_c;
begin
Result := Copy(Keccak_c);
end;
  
//------------------------------------------------------------------------------

class Function TKeccak_CHash.Keccak_cFromLE(Keccak_c: TKeccak_c): TKeccak_c;
begin
Result := Copy(Keccak_c);
end;
 
//------------------------------------------------------------------------------

class Function TKeccak_CHash.Keccak_cFromBE(Keccak_c: TKeccak_c): TKeccak_c;
begin
Result := Copy(Keccak_c);
end;

//------------------------------------------------------------------------------

class Function TKeccak_CHash.HashName: String;
begin
Result := 'Keccak[c]'
end;

//------------------------------------------------------------------------------

class Function TKeccak_CHash.HashFunction: TKeccakFunction;
begin
Result := fnKECCAK_c;
end;
 
//------------------------------------------------------------------------------

constructor TKeccak_CHash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TKeccak_CHash then
  fKeccak_c := TKeccak_CHash(Hash).Keccak_c // no need to call copy
else
  raise ESHA3IncompatibleClass.CreateFmt('TKeccak_CHash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;
 
//------------------------------------------------------------------------------

constructor TKeccak_CHash.CreateAndInitFrom(Hash: TKeccak);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then
      fKeccak_c := Copy(Hash.HashData)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TKeccak_CHash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TKeccak_CHash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
  
//------------------------------------------------------------------------------

constructor TKeccak_CHash.CreateAndInitFrom(Hash: TKeccak_c);
begin
CreateAndInit;
fKeccak_c := Copy(Hash);
end;
   
//------------------------------------------------------------------------------

procedure TKeccak_CHash.FromStringDef(const Str: String; const Default: TKeccak_c);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fKeccak_c := Copy(Default);
end;


{-------------------------------------------------------------------------------
================================================================================
                                    TSHA3Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3Hash - class declaration
===============================================================================}
{-------------------------------------------------------------------------------
    TSHA3Hash - protected methods
-------------------------------------------------------------------------------}

class Function TSHA3Hash.CapacityFromHashBits(Bits: UInt32): UInt32;
begin
If (Bits > 0) and (Bits < (25 * 4 * SizeOf(TKeccakWord){800})) then
  Result := Bits * 2
else
  raise ESHA3InvalidBits.CreateFmt('TSHA3Hash.CapacityFromHashBits: Invalid hash bits (%d).',[Bits]);
end;
   
//------------------------------------------------------------------------------

class Function TSHA3Hash.PaddingByte: UInt8;
begin
Result := $06;  // SHA3 padding (M || 01 || pad10*1)
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_224Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_224Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TSHA3_224Hash - protected methods
-------------------------------------------------------------------------------}

Function TSHA3_224Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fSHA3_224,Result[0],HashSize);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_224Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fSHA3_224,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TSHA3_224Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_224Hash.Initialize;
begin
SetHashBits(224);
inherited;
end;

{-------------------------------------------------------------------------------
    TSHA3_224Hash - public methods
-------------------------------------------------------------------------------}

class Function TSHA3_224Hash.SHA3_224ToLE(SHA3_224: TSHA3_224): TSHA3_224;
begin
Result := SHA3_224;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_224Hash.SHA3_224ToBE(SHA3_224: TSHA3_224): TSHA3_224;
begin
Result := SHA3_224;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_224Hash.SHA3_224FromLE(SHA3_224: TSHA3_224): TSHA3_224;
begin
Result := SHA3_224;
end;
      
//------------------------------------------------------------------------------

class Function TSHA3_224Hash.SHA3_224FromBE(SHA3_224: TSHA3_224): TSHA3_224;
begin
Result := SHA3_224;
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_224Hash.HashName: String;
begin
Result := 'SHA3-224';
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_224Hash.HashFunction: TKeccakFunction;
begin
Result := fnSHA3_224;
end;
     
//------------------------------------------------------------------------------

constructor TSHA3_224Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TSHA3_224Hash then
  fSHA3_224 := TSHA3_224Hash(Hash).SHA3_224
else
  raise ESHA3IncompatibleClass.CreateFmt('TSHA3_224Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_224Hash.CreateAndInitFrom(Hash: TSHA3);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then
      Move(Hash.HashData[0],fSHA3_224,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TSHA3_224Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TSHA3_224Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_224Hash.CreateAndInitFrom(Hash: TSHA3_224);
begin
CreateAndInit;
fSHA3_224 := Hash;
end;
     
//------------------------------------------------------------------------------

procedure TSHA3_224Hash.FromStringDef(const Str: String; const Default: TSHA3_224);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fSHA3_224 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_256Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_256Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TSHA3_256Hash - protected methods
-------------------------------------------------------------------------------}

Function TSHA3_256Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fSHA3_256,Result[0],HashSize);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_256Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fSHA3_256,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TSHA3_256Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_256Hash.Initialize;
begin
SetHashBits(256);
inherited;
end;

{-------------------------------------------------------------------------------
    TSHA3_256Hash - public methods
-------------------------------------------------------------------------------}

class Function TSHA3_256Hash.SHA3_256ToLE(SHA3_256: TSHA3_256): TSHA3_256;
begin
Result := SHA3_256;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_256Hash.SHA3_256ToBE(SHA3_256: TSHA3_256): TSHA3_256;
begin
Result := SHA3_256;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_256Hash.SHA3_256FromLE(SHA3_256: TSHA3_256): TSHA3_256;
begin
Result := SHA3_256;
end;
      
//------------------------------------------------------------------------------

class Function TSHA3_256Hash.SHA3_256FromBE(SHA3_256: TSHA3_256): TSHA3_256;
begin
Result := SHA3_256;
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_256Hash.HashName: String;
begin
Result := 'SHA3-256';
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_256Hash.HashFunction: TKeccakFunction;
begin
Result := fnSHA3_256;
end;
     
//------------------------------------------------------------------------------

constructor TSHA3_256Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TSHA3_256Hash then
  fSHA3_256 := TSHA3_256Hash(Hash).SHA3_256
else
  raise ESHA3IncompatibleClass.CreateFmt('TSHA3_256Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_256Hash.CreateAndInitFrom(Hash: TSHA3);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then
      Move(Hash.HashData[0],fSHA3_256,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TSHA3_256Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TSHA3_256Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_256Hash.CreateAndInitFrom(Hash: TSHA3_256);
begin
CreateAndInit;
fSHA3_256 := Hash;
end;
     
//------------------------------------------------------------------------------

procedure TSHA3_256Hash.FromStringDef(const Str: String; const Default: TSHA3_256);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fSHA3_256 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_384Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_384Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TSHA3_384Hash - protected methods
-------------------------------------------------------------------------------}

Function TSHA3_384Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fSHA3_384,Result[0],HashSize);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_384Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fSHA3_384,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TSHA3_384Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_384Hash.Initialize;
begin
SetHashBits(384);
inherited;
end;

{-------------------------------------------------------------------------------
    TSHA3_384Hash - public methods
-------------------------------------------------------------------------------}

class Function TSHA3_384Hash.SHA3_384ToLE(SHA3_384: TSHA3_384): TSHA3_384;
begin
Result := SHA3_384;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_384Hash.SHA3_384ToBE(SHA3_384: TSHA3_384): TSHA3_384;
begin
Result := SHA3_384;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_384Hash.SHA3_384FromLE(SHA3_384: TSHA3_384): TSHA3_384;
begin
Result := SHA3_384;
end;
      
//------------------------------------------------------------------------------

class Function TSHA3_384Hash.SHA3_384FromBE(SHA3_384: TSHA3_384): TSHA3_384;
begin
Result := SHA3_384;
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_384Hash.HashName: String;
begin
Result := 'SHA3-384';
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_384Hash.HashFunction: TKeccakFunction;
begin
Result := fnSHA3_384;
end;
     
//------------------------------------------------------------------------------

constructor TSHA3_384Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TSHA3_384Hash then
  fSHA3_384 := TSHA3_384Hash(Hash).SHA3_384
else
  raise ESHA3IncompatibleClass.CreateFmt('TSHA3_384Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_384Hash.CreateAndInitFrom(Hash: TSHA3);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then
      Move(Hash.HashData[0],fSHA3_384,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TSHA3_384Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TSHA3_384Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_384Hash.CreateAndInitFrom(Hash: TSHA3_384);
begin
CreateAndInit;
fSHA3_384 := Hash;
end;
     
//------------------------------------------------------------------------------

procedure TSHA3_384Hash.FromStringDef(const Str: String; const Default: TSHA3_384);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fSHA3_384 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                 TSHA3_512Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHA3_512Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TSHA3_512Hash - protected methods
-------------------------------------------------------------------------------}

Function TSHA3_512Hash.GetHashBuffer: TKeccak_Variable;
begin
SetLength(Result,HashSize);
Move(fSHA3_512,Result[0],HashSize);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_512Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  Move(HashBuffer[0],fSHA3_512,HashSize)
else
  raise ESHA3IncompatibleSize.CreateFmt('TSHA3_512Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;
   
//------------------------------------------------------------------------------

procedure TSHA3_512Hash.Initialize;
begin
SetHashBits(512);
inherited;
end;

{-------------------------------------------------------------------------------
    TSHA3_512Hash - public methods
-------------------------------------------------------------------------------}

class Function TSHA3_512Hash.SHA3_512ToLE(SHA3_512: TSHA3_512): TSHA3_512;
begin
Result := SHA3_512;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_512Hash.SHA3_512ToBE(SHA3_512: TSHA3_512): TSHA3_512;
begin
Result := SHA3_512;
end;
    
//------------------------------------------------------------------------------

class Function TSHA3_512Hash.SHA3_512FromLE(SHA3_512: TSHA3_512): TSHA3_512;
begin
Result := SHA3_512;
end;
      
//------------------------------------------------------------------------------

class Function TSHA3_512Hash.SHA3_512FromBE(SHA3_512: TSHA3_512): TSHA3_512;
begin
Result := SHA3_512;
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_512Hash.HashName: String;
begin
Result := 'SHA3-512';
end;
     
//------------------------------------------------------------------------------

class Function TSHA3_512Hash.HashFunction: TKeccakFunction;
begin
Result := fnSHA3_512;
end;
     
//------------------------------------------------------------------------------

constructor TSHA3_512Hash.CreateAndInitFrom(Hash: THashBase);
begin
inherited CreateAndInitFrom(Hash);
If Hash is TSHA3_512Hash then
  fSHA3_512 := TSHA3_512Hash(Hash).SHA3_512
else
  raise ESHA3IncompatibleClass.CreateFmt('TSHA3_512Hash.CreateAndInitFrom: Incompatible class (%s).',[Hash.ClassName]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_512Hash.CreateAndInitFrom(Hash: TSHA3);
begin
CreateAndInit;
If Hash.HashFunction = HashFunction then
  begin
    If (UInt32(Length(Hash.HashData)) = HashSize) then
      Move(Hash.HashData[0],fSHA3_512,HashSize)
    else
      raise ESHA3IncompatibleSize.CreateFmt('TSHA3_512Hash.CreateAndInitFrom: Incompatible size (%d).',[Length(Hash.HashData)]);
  end
else raise ESHA3IncompatibleFunction.CreateFmt('TSHA3_512Hash.CreateAndInitFrom: Incompatible function (%d).',[Ord(Hash.HashFunction)]);
end;
   
//------------------------------------------------------------------------------

constructor TSHA3_512Hash.CreateAndInitFrom(Hash: TSHA3_512);
begin
CreateAndInit;
fSHA3_512 := Hash;
end;
     
//------------------------------------------------------------------------------

procedure TSHA3_512Hash.FromStringDef(const Str: String; const Default: TSHA3_512);
begin
inherited FromStringDef(Str,Default);
If not TryFromString(Str) then
  fSHA3_512 := Default;
end;


{-------------------------------------------------------------------------------
================================================================================
                                   TSHAKEHash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHAKEHash - class declaration
===============================================================================}
{-------------------------------------------------------------------------------
    TSHAKEHash - protected methods
-------------------------------------------------------------------------------}

procedure TSHAKEHash.SetHashBits(Value: UInt32);
begin
If (Value mod 8) = 0 then
  begin
    fHashBits := Value;
    fCapacity := CapacityFromHashBits(fHashBits);
    fBlockSize := Bitrate div 8;
  end
else raise ESHA3InvalidBits.CreateFmt('TSHAKEHash.SetHashBits: Invalid hash bits (%d).',[Value]);
end;

//------------------------------------------------------------------------------

class Function TSHAKEHash.PaddingByte: UInt8;
begin
Result := $1F;  // RawSHAKE + SHAKE padding (M || 11 || 11 || pad10*1)
end;


{-------------------------------------------------------------------------------
================================================================================
                                  TSHAKE128Hash
================================================================================
-------------------------------------------------------------------------------}
{===============================================================================
    TSHAKE128Hash - class implementation
===============================================================================}
{-------------------------------------------------------------------------------
    TSHAKE128Hash - protected methods
-------------------------------------------------------------------------------}

procedure TSHAKE128Hash.SetHashBits(Value: UInt32);
begin
inherited SetHashBits(Value);
ReallocMem(fTempBlock,fBlockSize);
SetLength(fSHAKE128,HashSize);
end;

//------------------------------------------------------------------------------

class Function TSHAKE128Hash.CapacityFromHashBits(Bits: UInt32): UInt32;
begin
Result := 256;
end;

//------------------------------------------------------------------------------

Function TSHAKE128Hash.GetHashBuffer: TKeccak_Variable;
begin
Result := Copy(TKeccak_Variable(fSHAKE128));
end;

//------------------------------------------------------------------------------

procedure TSHAKE128Hash.SetHashBuffer(HashBuffer: TKeccak_Variable);
begin
If UInt32(Length(HashBuffer)) = HashSize then
  fSHAKE128 := Copy(TSHAKE128(HashBuffer))
else
  raise ESHA3IncompatibleSize.CreateFmt('TSHAKE128Hash.SetHashBuffer: Incompatible size (%d).',[Length(HashBuffer)]);
end;
     
//------------------------------------------------------------------------------

procedure TSHAKE128Hash.Initialize;
begin
SetHashBits(128);
inherited;
end;

{-------------------------------------------------------------------------------
    TSHAKE128Hash - public methods
-------------------------------------------------------------------------------}

class Function TSHAKE128Hash.SHAKE128ToLE(SHAKE128: TSHAKE128): TSHAKE128;
begin
Result := Copy(SHAKE128);
end;
     
//------------------------------------------------------------------------------

class Function TSHAKE128Hash.SHAKE128ToBE(SHAKE128: TSHAKE128): TSHAKE128;
begin
Result := Copy(SHAKE128);
end;  
     
//------------------------------------------------------------------------------

class Function TSHAKE128Hash.SHAKE128FromLE(SHAKE128: TSHAKE128): TSHAKE128;
begin
Result := Copy(SHAKE128);
end; 
     
//------------------------------------------------------------------------------

class Function TSHAKE128Hash.SHAKE128FromBE(SHAKE128: TSHAKE128): TSHAKE128;
begin
Result := Copy(SHAKE128);
end; 
     
//------------------------------------------------------------------------------

class Function TSHAKE128Hash.HashName: String;
begin
Result := 'SHAKE128';
end;  
     
//------------------------------------------------------------------------------

class Function TSHAKE128Hash.HashFunction: TKeccakFunction;
begin
Result := fnSHAKE128;
end;  
     
//------------------------------------------------------------------------------

constructor TSHAKE128Hash.CreateAndInitFrom(Hash: THashBase);
begin
end;  
     
//------------------------------------------------------------------------------

constructor TSHAKE128Hash.CreateAndInitFrom(Hash: TKeccak);
begin
end;    
     
//------------------------------------------------------------------------------

constructor TSHAKE128Hash.CreateAndInitFrom(Hash: TSHAKE128);
begin
end;   
     
//------------------------------------------------------------------------------

procedure TSHAKE128Hash.FromStringDef(const Str: String; const Default: TSHAKE128);
begin
end;



(*
{$IFDEF FPC_DisableWarns}
  {$DEFINE FPCDWM}
  {$DEFINE W4055:={$WARN 4055 OFF}} // Conversion between ordinals and pointers is not portable
  {$DEFINE W4056:={$WARN 4056 OFF}} // Conversion between ordinals and pointers is not portable
  {$PUSH}{$WARN 2005 OFF} // Comment level $1 found
  {$IF Defined(FPC) and (FPC_FULLVERSION >= 30000)}
    {$DEFINE W5092:={$WARN 5092 OFF}} // Variable "$1" of a managed type does not seem to be initialized
  {$ELSE}
    {$DEFINE W5092:=}
  {$IFEND}
  {$POP}
{$ENDIF}

const
  RoundConsts: array[0..23] of UInt64 = (
    UInt64($0000000000000001), UInt64($0000000000008082), UInt64($800000000000808A),
    UInt64($8000000080008000), UInt64($000000000000808B), UInt64($0000000080000001),
    UInt64($8000000080008081), UInt64($8000000000008009), UInt64($000000000000008A),
    UInt64($0000000000000088), UInt64($0000000080008009), UInt64($000000008000000A),
    UInt64($000000008000808B), UInt64($800000000000008B), UInt64($8000000000008089),
    UInt64($8000000000008003), UInt64($8000000000008002), UInt64($8000000000000080),
    UInt64($000000000000800A), UInt64($800000008000000A), UInt64($8000000080008081),
    UInt64($8000000000008080), UInt64($0000000080000001), UInt64($8000000080008008));

  RotateCoefs: array[0..4,0..4] of UInt8 = ( // first index is X, second Y
    {X = 0} ( 0,36, 3,41,18),
    {X = 1} ( 1,44,10,45, 2),
    {X = 2} (62, 6,43,15,61),
    {X = 3} (28,55,25,21,56),
    {X = 4} (27,20,39, 8,14));

type
  TSHA3Context_Internal = record
    HashState:      TSHA3State;
    TransferSize:   UInt32;
    TransferBuffer: array[0..199] of UInt8;
  end;
  PSHA3Context_Internal = ^TSHA3Context_Internal;

//==============================================================================

procedure Permute(var State: TKeccakState);
var
  i:    Integer;
  B:    TKeccakSponge;
  C,D:  array[0..4] of UInt64;
begin
For i := 0 to 23 do // 24 rounds (12 + 2L; where L = log2(64) = 6; 64 is length of sponge word in bits)
  begin
    C[0] := State.Sponge[0,0] xor State.Sponge[1,0] xor State.Sponge[2,0] xor State.Sponge[3,0] xor State.Sponge[4,0];
    C[1] := State.Sponge[0,1] xor State.Sponge[1,1] xor State.Sponge[2,1] xor State.Sponge[3,1] xor State.Sponge[4,1];
    C[2] := State.Sponge[0,2] xor State.Sponge[1,2] xor State.Sponge[2,2] xor State.Sponge[3,2] xor State.Sponge[4,2];
    C[3] := State.Sponge[0,3] xor State.Sponge[1,3] xor State.Sponge[2,3] xor State.Sponge[3,3] xor State.Sponge[4,3];
    C[4] := State.Sponge[0,4] xor State.Sponge[1,4] xor State.Sponge[2,4] xor State.Sponge[3,4] xor State.Sponge[4,4];

    D[0] := C[4] xor ROL(C[1],1);
    D[1] := C[0] xor ROL(C[2],1);
    D[2] := C[1] xor ROL(C[3],1);
    D[3] := C[2] xor ROL(C[4],1);
    D[4] := C[3] xor ROL(C[0],1);

    State.Sponge[0,0] := State.Sponge[0,0] xor D[0];
    State.Sponge[0,1] := State.Sponge[0,1] xor D[1];
    State.Sponge[0,2] := State.Sponge[0,2] xor D[2];
    State.Sponge[0,3] := State.Sponge[0,3] xor D[3];
    State.Sponge[0,4] := State.Sponge[0,4] xor D[4];
    State.Sponge[1,0] := State.Sponge[1,0] xor D[0];
    State.Sponge[1,1] := State.Sponge[1,1] xor D[1];
    State.Sponge[1,2] := State.Sponge[1,2] xor D[2];
    State.Sponge[1,3] := State.Sponge[1,3] xor D[3];
    State.Sponge[1,4] := State.Sponge[1,4] xor D[4];
    State.Sponge[2,0] := State.Sponge[2,0] xor D[0];
    State.Sponge[2,1] := State.Sponge[2,1] xor D[1];
    State.Sponge[2,2] := State.Sponge[2,2] xor D[2];
    State.Sponge[2,3] := State.Sponge[2,3] xor D[3];
    State.Sponge[2,4] := State.Sponge[2,4] xor D[4];
    State.Sponge[3,0] := State.Sponge[3,0] xor D[0];
    State.Sponge[3,1] := State.Sponge[3,1] xor D[1];
    State.Sponge[3,2] := State.Sponge[3,2] xor D[2];
    State.Sponge[3,3] := State.Sponge[3,3] xor D[3];
    State.Sponge[3,4] := State.Sponge[3,4] xor D[4];
    State.Sponge[4,0] := State.Sponge[4,0] xor D[0];
    State.Sponge[4,1] := State.Sponge[4,1] xor D[1];
    State.Sponge[4,2] := State.Sponge[4,2] xor D[2];
    State.Sponge[4,3] := State.Sponge[4,3] xor D[3];
    State.Sponge[4,4] := State.Sponge[4,4] xor D[4];

    B[0,0] := ROL(State.Sponge[0,0],RotateCoefs[0,0]);
    B[2,0] := ROL(State.Sponge[0,1],RotateCoefs[1,0]);
    B[4,0] := ROL(State.Sponge[0,2],RotateCoefs[2,0]);
    B[1,0] := ROL(State.Sponge[0,3],RotateCoefs[3,0]);
    B[3,0] := ROL(State.Sponge[0,4],RotateCoefs[4,0]);
    B[3,1] := ROL(State.Sponge[1,0],RotateCoefs[0,1]);
    B[0,1] := ROL(State.Sponge[1,1],RotateCoefs[1,1]);
    B[2,1] := ROL(State.Sponge[1,2],RotateCoefs[2,1]);
    B[4,1] := ROL(State.Sponge[1,3],RotateCoefs[3,1]);
    B[1,1] := ROL(State.Sponge[1,4],RotateCoefs[4,1]);
    B[1,2] := ROL(State.Sponge[2,0],RotateCoefs[0,2]);
    B[3,2] := ROL(State.Sponge[2,1],RotateCoefs[1,2]);
    B[0,2] := ROL(State.Sponge[2,2],RotateCoefs[2,2]);
    B[2,2] := ROL(State.Sponge[2,3],RotateCoefs[3,2]);
    B[4,2] := ROL(State.Sponge[2,4],RotateCoefs[4,2]);
    B[4,3] := ROL(State.Sponge[3,0],RotateCoefs[0,3]);
    B[1,3] := ROL(State.Sponge[3,1],RotateCoefs[1,3]);
    B[3,3] := ROL(State.Sponge[3,2],RotateCoefs[2,3]);
    B[0,3] := ROL(State.Sponge[3,3],RotateCoefs[3,3]);
    B[2,3] := ROL(State.Sponge[3,4],RotateCoefs[4,3]);
    B[2,4] := ROL(State.Sponge[4,0],RotateCoefs[0,4]);
    B[4,4] := ROL(State.Sponge[4,1],RotateCoefs[1,4]);
    B[1,4] := ROL(State.Sponge[4,2],RotateCoefs[2,4]);
    B[3,4] := ROL(State.Sponge[4,3],RotateCoefs[3,4]);
    B[0,4] := ROL(State.Sponge[4,4],RotateCoefs[4,4]);

    State.Sponge[0,0] := B[0,0] xor ((not B[0,1]) and B[0,2]);
    State.Sponge[0,1] := B[0,1] xor ((not B[0,2]) and B[0,3]);
    State.Sponge[0,2] := B[0,2] xor ((not B[0,3]) and B[0,4]);
    State.Sponge[0,3] := B[0,3] xor ((not B[0,4]) and B[0,0]);
    State.Sponge[0,4] := B[0,4] xor ((not B[0,0]) and B[0,1]);
    State.Sponge[1,0] := B[1,0] xor ((not B[1,1]) and B[1,2]);
    State.Sponge[1,1] := B[1,1] xor ((not B[1,2]) and B[1,3]);
    State.Sponge[1,2] := B[1,2] xor ((not B[1,3]) and B[1,4]);
    State.Sponge[1,3] := B[1,3] xor ((not B[1,4]) and B[1,0]);
    State.Sponge[1,4] := B[1,4] xor ((not B[1,0]) and B[1,1]);
    State.Sponge[2,0] := B[2,0] xor ((not B[2,1]) and B[2,2]);
    State.Sponge[2,1] := B[2,1] xor ((not B[2,2]) and B[2,3]);
    State.Sponge[2,2] := B[2,2] xor ((not B[2,3]) and B[2,4]);
    State.Sponge[2,3] := B[2,3] xor ((not B[2,4]) and B[2,0]);
    State.Sponge[2,4] := B[2,4] xor ((not B[2,0]) and B[2,1]);
    State.Sponge[3,0] := B[3,0] xor ((not B[3,1]) and B[3,2]);
    State.Sponge[3,1] := B[3,1] xor ((not B[3,2]) and B[3,3]);
    State.Sponge[3,2] := B[3,2] xor ((not B[3,3]) and B[3,4]);
    State.Sponge[3,3] := B[3,3] xor ((not B[3,4]) and B[3,0]);
    State.Sponge[3,4] := B[3,4] xor ((not B[3,0]) and B[3,1]);
    State.Sponge[4,0] := B[4,0] xor ((not B[4,1]) and B[4,2]);
    State.Sponge[4,1] := B[4,1] xor ((not B[4,2]) and B[4,3]);
    State.Sponge[4,2] := B[4,2] xor ((not B[4,3]) and B[4,4]);
    State.Sponge[4,3] := B[4,3] xor ((not B[4,4]) and B[4,0]);
    State.Sponge[4,4] := B[4,4] xor ((not B[4,0]) and B[4,1]);

    State.Sponge[0,0] := State.Sponge[0,0] xor RoundConsts[i];
  end;
end;

//------------------------------------------------------------------------------

procedure BlockHash(var State: TKeccakState; const Block);
var
  i:    Integer;
  Buff: TKeccakSpongeOverlay absolute Block;
begin
For i := 0 to Pred(State.BlockSize shr 3) do
  TKeccakSpongeOverlay(State.Sponge)[i] := TKeccakSpongeOverlay(State.Sponge)[i] xor Buff[i];
Permute(State);
end;

//------------------------------------------------------------------------------

procedure Squeeze(var State: TKeccakState; var Buffer);
var
  BytesToSqueeze: UInt32;
begin
BytesToSqueeze := State.HashBits shr 3;
If BytesToSqueeze > State.BlockSize then
  while BytesToSqueeze > 0 do
    begin
    {$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
      Move(State.Sponge,Pointer(PtrUInt(@Buffer) + UInt64(State.HashBits shr 3) - BytesToSqueeze)^,Min(BytesToSqueeze,State.BlockSize));
    {$IFDEF FPCDWM}{$POP}{$ENDIF}
      Permute(State);
      Dec(BytesToSqueeze,Min(BytesToSqueeze,State.BlockSize));
    end
else Move(State.Sponge,Buffer,BytesToSqueeze);
end;

//==============================================================================

procedure PrepareHash(State: TSHA3State; out Hash: TSHA3Hash);
begin
Hash.HashSize := State.HashSize;
Hash.HashBits := State.HashBits;
SetLength(Hash.HashData,Hash.HashBits shr 3);
end;

//==============================================================================

Function GetBlockSize(HashSize: TKeccakHashSize): UInt32;
begin
case HashSize of
  Keccak224, SHA3_224:  Result := (1600 - (2 * 224)) shr 3;
  Keccak256, SHA3_256:  Result := (1600 - (2 * 256)) shr 3;
  Keccak384, SHA3_384:  Result := (1600 - (2 * 384)) shr 3;
  Keccak512, SHA3_512:  Result := (1600 - (2 * 512)) shr 3;
  Keccak_b:             Result := (1600 - 576) shr 3;
  SHAKE128:             Result := (1600 - (2 * 128)) shr 3;
  SHAKE256:             Result := (1600 - (2 * 256)) shr 3;
else
  raise Exception.CreateFmt('GetBlockSize: Unknown hash size (%d).',[Ord(HashSize)]);
end;
end;

//------------------------------------------------------------------------------

Function InitialSHA3State(HashSize: TSHA3HashSize; HashBits: UInt32 = 0): TSHA3State;
begin
Result.HashSize := HashSize;
case HashSize of
  Keccak224, SHA3_224:  Result.HashBits := 224;
  Keccak256, SHA3_256:  Result.HashBits := 256;
  Keccak384, SHA3_384:  Result.HashBits := 384;
  Keccak512, SHA3_512:  Result.HashBits := 512;
  Keccak_b,
  SHAKE128,
  SHAKE256: begin
              If (HashBits and $7) <> 0 then
                raise Exception.Create('InitialSHA3State: HashBits must be divisible by 8.')
              else
                Result.HashBits := HashBits;
            end;
else
  raise Exception.CreateFmt('InitialSHA3State: Unknown hash size (%d).',[Ord(HashSize)]);
end;
Result.BlockSize := GetBlockSize(HashSize);
FillChar(Result.Sponge,SizeOf(Result.Sponge),0);
end;

//==============================================================================

Function SHA3ToStr(Hash: TSHA3Hash): String;
var
  i:  Integer;
begin
SetLength(Result,Length(Hash.HashData) * 2);
For i := Low(Hash.HashData) to High(Hash.HashData) do
  begin
    Result[(i * 2) + 1] := IntToHex(Hash.HashData[i],2)[1];
    Result[(i * 2) + 2] := IntToHex(Hash.HashData[i],2)[2];
  end;
end;

//------------------------------------------------------------------------------

{$IFDEF FPCDWM}{$PUSH}W5092{$ENDIF}
Function StrToSHA3(HashSize: TSHA3HashSize; Str: String): TSHA3Hash;
var
  HashCharacters: Integer;
  i:              Integer;
begin
Result.HashSize := HashSize;
case HashSize of
  Keccak224, SHA3_224:  Result.HashBits := 224;
  Keccak256, SHA3_256:  Result.HashBits := 256;
  Keccak384, SHA3_384:  Result.HashBits := 384;
  Keccak512, SHA3_512:  Result.HashBits := 512;
  Keccak_b,
  SHAKE128,
  SHAKE256:  Result.HashBits := (Length(Str) shr 1) shl 3;
else
  raise Exception.CreateFmt('StrToSHA3: Unknown source hash size (%d).',[Ord(HashSize)]);
end;
HashCharacters := Result.HashBits shr 2;
If Length(Str) < HashCharacters then
  Str := StringOfChar('0',HashCharacters - Length(Str)) + Str
else
  If Length(Str) > HashCharacters then
    Str := Copy(Str,Length(Str) - HashCharacters + 1,HashCharacters);
SetLength(Result.HashData,Length(Str) shr 1);    
For i := Low(Result.HashData) to High(Result.HashData) do
  Result.HashData[i] := UInt8(StrToInt('$' + Copy(Str,(i * 2) + 1,2)));
end;
{$IFDEF FPCDWM}{$POP}{$ENDIF}

//------------------------------------------------------------------------------

Function TryStrToSHA3(HashSize: TSHA3HashSize; const Str: String; out Hash: TSHA3Hash): Boolean;
begin
try
  Hash := StrToSHA3(HashSize,Str);
  Result := True;
except
  Result := False;
end;
end;

//------------------------------------------------------------------------------

Function StrToSHA3Def(HashSize: TSHA3HashSize; const Str: String; Default: TSHA3Hash): TSHA3Hash;
begin
If not TryStrToSHA3(HashSize,Str,Result) then
  Result := Default;
end;

//------------------------------------------------------------------------------

Function CompareSHA3(A,B: TSHA3Hash): Integer;
var
  i:  Integer;
begin
Result := 0;
If (A.HashBits = B.HashBits) and (A.HashSize = B.HashSize) and
  (Length(A.HashData) = Length(B.HashData)) then
  begin
    For i := Low(A.HashData) to High(A.HashData) do
      begin
        If A.HashData[i] < B.HashData[i] then
          begin
            Result := -1;
            Break;
          end
        else If A.HashData[i] > B.HashData[i] then
          begin
            Result := 1;
            Break;
          end;
      end;
  end
else raise Exception.Create('CompareSHA3: Cannot compare different hashes.');
end;

//------------------------------------------------------------------------------

Function SameSHA3(A,B: TSHA3Hash): Boolean;
var
  i:  Integer;
begin
Result := False;
If (A.HashBits = B.HashBits) and (A.HashSize = B.HashSize) and
  (Length(A.HashData) = Length(B.HashData)) then
  begin
    For i := Low(A.HashData) to High(A.HashData) do
      If A.HashData[i] <> B.HashData[i] then Exit;
    Result := True;
  end;
end;

//------------------------------------------------------------------------------

Function BinaryCorrectSHA3(Hash: TSHA3Hash): TSHA3Hash;
begin
Result := Hash;
end;

//==============================================================================

procedure BufferSHA3(var State: TSHA3State; const Buffer; Size: TMemSize);
var
  i:    TMemSize;
  Buff: PUInt8;
begin
If Size > 0 then
  begin
    If (Size mod State.BlockSize) = 0 then
      begin
        Buff := @Buffer;
        For i := 0 to Pred(Size div State.BlockSize) do
          begin
            BlockHash(State,Buff^);
            Inc(Buff,State.BlockSize);
          end;
      end
    else raise Exception.CreateFmt('BufferSHA3: Buffer size is not divisible by %d.',[State.BlockSize]);
  end;
end;

//------------------------------------------------------------------------------

Function LastBufferSHA3(State: TSHA3State; const Buffer; Size: TMemSize): TSHA3Hash;
var
  FullBlocks:     TMemSize;
  LastBlockSize:  TMemSize;
  HelpBlocks:     TMemSize;
  HelpBlocksBuff: Pointer;
begin
FullBlocks := Size div State.BlockSize;
If FullBlocks > 0 then BufferSHA3(State,Buffer,FullBlocks * State.BlockSize);
LastBlockSize := Size - (UInt64(FullBlocks) * State.BlockSize);
HelpBlocks := Ceil((LastBlockSize + 1) / State.BlockSize);
HelpBlocksBuff := AllocMem(HelpBlocks * State.BlockSize);
try
{$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
  Move(Pointer(PtrUInt(@Buffer) + (FullBlocks * State.BlockSize))^,HelpBlocksBuff^,LastBlockSize);
  case State.HashSize of
    Keccak224..Keccak_b:  PUInt8(PtrUInt(HelpBlocksBuff) + LastBlockSize)^ := $01;
     SHA3_224..SHA3_512:  PUInt8(PtrUInt(HelpBlocksBuff) + LastBlockSize)^ := $06;
     SHAKE128..SHAKE256:  PUInt8(PtrUInt(HelpBlocksBuff) + LastBlockSize)^ := $1F;
  else
    raise Exception.CreateFmt('LastBufferSHA3: Unknown hash size (%d)',[Ord(State.HashSize)]);
  end;
  PUInt8(PtrUInt(HelpBlocksBuff) + (UInt64(HelpBlocks) * State.BlockSize) - 1)^ := PUInt8(PtrUInt(HelpBlocksBuff) + (UInt64(HelpBlocks) * State.BlockSize) - 1)^ xor $80;
  BufferSHA3(State,HelpBlocksBuff^,HelpBlocks * State.BlockSize);
{$IFDEF FPCDWM}{$POP}{$ENDIF}
finally
  FreeMem(HelpBlocksBuff,HelpBlocks * State.BlockSize);
end;
PrepareHash(State,Result);
If Length(Result.HashData) > 0 then
  Squeeze(State,Addr(Result.HashData[0])^);
end;

//==============================================================================

Function BufferSHA3(HashSize: TSHA3HashSize; const Buffer; Size: TMemSize; HashBits: UInt32 = 0): TSHA3Hash;
begin
Result := LastBufferSHA3(InitialSHA3State(HashSize,HashBits),Buffer,Size);
end;

//==============================================================================

Function AnsiStringSHA3(HashSize: TSHA3HashSize; const Str: AnsiString; HashBits: UInt32 = 0): TSHA3Hash;
begin
Result := BufferSHA3(HashSize,PAnsiChar(Str)^,Length(Str) * SizeOf(AnsiChar),HashBits);
end;

//------------------------------------------------------------------------------

Function WideStringSHA3(HashSize: TSHA3HashSize; const Str: WideString; HashBits: UInt32 = 0): TSHA3Hash;
begin
Result := BufferSHA3(HashSize,PWideChar(Str)^,Length(Str) * SizeOf(WideChar),HashBits);
end;

//------------------------------------------------------------------------------

Function StringSHA3(HashSize: TSHA3HashSize; const Str: String; HashBits: UInt32 = 0): TSHA3Hash;
begin
Result := BufferSHA3(HashSize,PChar(Str)^,Length(Str) * SizeOf(Char),HashBits);
end;

//==============================================================================

Function StreamSHA3(HashSize: TSHA3HashSize; Stream: TStream; Count: Int64 = -1; HashBits: UInt32 = 0): TSHA3Hash;
var
  Buffer:     Pointer;
  BytesRead:  UInt32;
  State:      TSHA3State;
  BufferSize: UInt32;
begin
If Assigned(Stream) then
  begin
    If Count = 0 then
      Count := Stream.Size - Stream.Position;
    If Count < 0 then
      begin
        Stream.Position := 0;
        Count := Stream.Size;
      end;
  {$IFDEF LargeBuffer}
    BufferSize := ($100000 div GetBlockSize(HashSize)) * GetBlockSize(HashSize);
  {$ELSE}
    BufferSize := ($1000 div GetBlockSize(HashSize)) * GetBlockSize(HashSize);
  {$ENDIF}
    GetMem(Buffer,BufferSize);
    try
      State := InitialSHA3State(HashSize,HashBits);
      repeat
        BytesRead := Stream.Read(Buffer^,Min(BufferSize,Count));
        If BytesRead < BufferSize then
          Result := LastBufferSHA3(State,Buffer^,BytesRead)
        else
          BufferSHA3(State,Buffer^,BytesRead);
        Dec(Count,BytesRead);
      until BytesRead < BufferSize;
    finally
      FreeMem(Buffer,BufferSize);
    end;
  end
else raise Exception.Create('StreamSHA3: Stream is not assigned.');
end;

//------------------------------------------------------------------------------

Function FileSHA3(HashSize: TSHA3HashSize; const FileName: String; HashBits: UInt32 = 0): TSHA3Hash;
var
  FileStream: TFileStream;
begin
FileStream := TFileStream.Create(StrToRTL(FileName), fmOpenRead or fmShareDenyWrite);
try
  Result := StreamSHA3(HashSize,FileStream,-1,HashBits);
finally
  FileStream.Free;
end;
end;

//==============================================================================

Function SHA3_Init(HashSize: TSHA3HashSize; HashBits: UInt32 = 0): TSHA3Context;
begin
Result := AllocMem(SizeOf(TSHA3Context_Internal));
with PSHA3Context_Internal(Result)^ do
  begin
    HashState := InitialSHA3State(HashSize,HashBits);
    TransferSize := 0;
  end;
end;

//------------------------------------------------------------------------------

procedure SHA3_Update(Context: TSHA3Context; const Buffer; Size: TMemSize);
var
  FullBlocks:     TMemSize;
  RemainingSize:  TMemSize;
begin
with PSHA3Context_Internal(Context)^ do
  begin
    If TransferSize > 0 then
      begin
        If Size >= (HashState.BlockSize - TransferSize) then
          begin
            Move(Buffer,TransferBuffer[TransferSize],HashState.BlockSize - TransferSize);
            BufferSHA3(HashState,TransferBuffer,HashState.BlockSize);
            RemainingSize := Size - (HashState.BlockSize - TransferSize);
            TransferSize := 0;
          {$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
            SHA3_Update(Context,Pointer(PtrUInt(@Buffer) + (Size - RemainingSize))^,RemainingSize);
          {$IFDEF FPCDWM}{$POP}{$ENDIF}
          end
        else
          begin
            Move(Buffer,TransferBuffer[TransferSize],Size);
            Inc(TransferSize,Size);
          end;  
      end
    else
      begin
        FullBlocks := Size div HashState.BlockSize;
        BufferSHA3(HashState,Buffer,FullBlocks * HashState.BlockSize);
        If (FullBlocks * HashState.BlockSize) < Size then
          begin
            TransferSize := Size - (UInt64(FullBlocks) * HashState.BlockSize);
          {$IFDEF FPCDWM}{$PUSH}W4055 W4056{$ENDIF}
            Move(Pointer(PtrUInt(@Buffer) + (Size - TransferSize))^,TransferBuffer,TransferSize);
          {$IFDEF FPCDWM}{$POP}{$ENDIF}
          end;
      end;
  end;
end;

//------------------------------------------------------------------------------

Function SHA3_Final(var Context: TSHA3Context; const Buffer; Size: TMemSize): TSHA3Hash;
begin
SHA3_Update(Context,Buffer,Size);
Result := SHA3_Final(Context);
end;

//------------------------------------------------------------------------------

Function SHA3_Final(var Context: TSHA3Context): TSHA3Hash;
begin
with PSHA3Context_Internal(Context)^ do
  Result := LastBufferSHA3(HashState,TransferBuffer,TransferSize);
FreeMem(Context,SizeOf(TSHA3Context_Internal));
Context := nil;
end;

//------------------------------------------------------------------------------

Function SHA3_Hash(HashSize: TSHA3HashSize; const Buffer; Size: TMemSize; HashBits: UInt32 = 0): TSHA3Hash;
begin
Result := LastBufferSHA3(InitialSHA3State(HashSize,HashBits),Buffer,Size);
end;
*)
end.

