unit SHA3;

interface

{$DEFINE LargeBuffer}
{.$DEFINE UseStringStream}

uses
  Classes;

type
{$IFDEF x64}
  TSize = UInt64;
{$ELSE}
  TSize = LongWord;
{$ENDIF}

  TKeccakHashSize = (Keccak224,Keccak256,Keccak384,Keccak512,Keccak_b,
                     SHA3_224,SHA3_256,SHA3_384,SHA3_512,SHAKE128,SHAKE256);
                     
  TSHA3HashSize = TKeccakHashSize;

  TKeccakSponge = Array[0..4,0..4] of Int64;  // First index is Y, second X

  TKeccakState = record
    HashSize:   TKeccakHashSize;
    HashBits:   LongWord;
    BlockSize:  LongWord;
    Sponge:     TKeccakSponge;
  end;

  TSHA3State = TKeccakState;

  TKeccakHash_224 = Array[0..27] of Byte;
  TKeccakHash_256 = Array[0..31] of Byte;
  TKeccakHash_384 = Array[0..47] of Byte;
  TKeccakHash_512 = Array[0..63] of Byte;

  TSHA3Hash_224 = TKeccakHash_224;
  TSHA3Hash_256 = TKeccakHash_256;
  TSHA3Hash_384 = TKeccakHash_384;
  TSHA3Hash_512 = TKeccakHash_512;

  TKeccakHash = record
    HashPtr:  Pointer;
    HashBits: LongWord;
    case HashSize: TKeccakHashSize of
      Keccak224:  (KeccakHash_224:  TKeccakHash_224);
      Keccak256:  (KeccakHash_256:  TKeccakHash_256);
      Keccak384:  (KeccakHash_384:  TKeccakHash_384);
      Keccak512:  (KeccakHash_512:  TKeccakHash_512);
      SHA3_224:   (SHA3Hash_224:    TSHA3Hash_224);
      SHA3_256:   (SHA3Hash_256:    TSHA3Hash_256);
      SHA3_384:   (SHA3Hash_384:    TSHA3Hash_384);
      SHA3_512:   (SHA3Hash_512:    TSHA3Hash_512);
  end;

  TSHA3Hash = TKeccakHash;

Function GetBlockSize(HashSize: TSHA3HashSize): LongWord;

Function InitialSHA3State(HashSize: TSHA3HashSize; HashBits: LongWord = 0): TSHA3State;
procedure CopySHA3Hash(Source: TSHA3Hash; var Destination: TSHA3Hash);
procedure FinalizeSHA3Hash(var Hash: TSHA3Hash);

Function SHA3ToStr(Hash: TSHA3Hash): String;
Function StrToSHA3(HashSize: TSHA3HashSize; Str: String): TSHA3Hash;
Function TryStrToSHA3(HashSize: TSHA3HashSize;const Str: String; out Hash: TSHA3Hash): Boolean;
Function StrToSHA3Def(HashSize: TSHA3HashSize;const Str: String; Default: TSHA3Hash): TSHA3Hash;
Function SameSHA3(A,B: TSHA3Hash): Boolean;

procedure BufferSHA3(var State: TSHA3State; const Buffer; Size: TSize); overload;
Function LastBufferSHA3(State: TSHA3State; const Buffer; Size: TSize): TSHA3Hash;

Function BufferSHA3(HashSize: TSHA3HashSize; const Buffer; Size: TSize; HashBits: LongWord = 0): TSHA3Hash; overload;

Function AnsiStringSHA3(HashSize: TSHA3HashSize; const Str: AnsiString; HashBits: LongWord = 0): TSHA3Hash;
Function WideStringSHA3(HashSize: TSHA3HashSize; const Str: WideString; HashBits: LongWord = 0): TSHA3Hash;
Function StringSHA3(HashSize: TSHA3HashSize; const Str: String; HashBits: LongWord = 0): TSHA3Hash;

Function StreamSHA3(HashSize: TSHA3HashSize; Stream: TStream; Count: Int64 = -1; HashBits: LongWord = 0): TSHA3Hash;
Function FileSHA3(HashSize: TSHA3HashSize; const FileName: String; HashBits: LongWord = 0): TSHA3Hash;


implementation

uses
  SysUtils, Math;

const
  RoundConsts: Array[0..23] of Int64 = (
    $0000000000000001, $0000000000008082, $800000000000808A, $8000000080008000,
    $000000000000808B, $0000000080000001, $8000000080008081, $8000000000008009,
    $000000000000008A, $0000000000000088, $0000000080008009, $000000008000000A,
    $000000008000808B, $800000000000008B, $8000000000008089, $8000000000008003,
    $8000000000008002, $8000000000000080, $000000000000800A, $800000008000000A,
    $8000000080008081, $8000000000008080, $0000000080000001, $8000000080008008);


  RotateCoefs: Array[0..4,0..4] of Byte = ( // first index is X, second Y
    {X = 0} ( 0,36, 3,41,18),
    {X = 1} ( 1,44,10,45, 2),
    {X = 2} (62, 6,43,15,61),
    {X = 3} (28,55,25,21,56),
    {X = 4} (27,20,39, 8,14));

//==============================================================================    

{$If Defined(PurePascal) or not Defined(x64)}
  {$DEFINE no32ASM}
{$IFEND}

Function ROL(Value: Int64; Shift: Integer): Int64;{$IFNDEF no32ASM}assembler;{$ENDIF}
{$IFDEF no32ASM}
begin
  Result := (Value shl Shift) or (Value shr (64 - Shift));
end;
{$ELSE}
asm
  MOV RAX, RCX
  MOV CL,  DL
  ROL RAX, CL
end;
{$ENDIF}

//==============================================================================

procedure Permute(var State: TKeccakState);
var
  i,x,y:  Integer;
  B:      TKeccakSponge;
  C,D:    Array[0..4] of Int64;

  Function WrapIndex(Idx: Integer): Integer;
  begin
    If Idx > 4 then
      while Idx > 4 do Dec(Idx,5)
    else If Idx < 0 then
      while idx < 0 do Inc(Idx,5);
    Result := Idx;
  end;

begin
For i := 0 to 23 do // 24 rounds (12 + 2L; where L = log2(64) = 6; 64 is length of sponge word in bits)
  begin
    For x := 0 to 4 do
      C[x] := State.Sponge[0,x] xor State.Sponge[1,x] xor State.Sponge[2,x] xor State.Sponge[3,x] xor State.Sponge[4,x];

    For x := 0 to 4 do
      D[x] := C[WrapIndex(x - 1)] xor ROL(C[WrapIndex(x + 1)],1);
    For x := 0 to 4 do
      For y := 0 to 4 do
        State.Sponge[y,x] := State.Sponge[y,x] xor D[x];

    For x := 0 to 4 do
      For y := 0 to 4 do
        B[WrapIndex(2 *x + 3 * y),y] := ROL(State.Sponge[y,x],RotateCoefs[x,y]);

    For x := 0 to 4 do
      For y := 0 to 4 do
        State.Sponge[y,x] := B[y,x] xor ((not B[y,WrapIndex(x + 1)]) and B[y,WrapIndex(x + 2)]);

    State.Sponge[0,0] := State.Sponge[0,0] xor RoundConsts[i];
  end;
end;

//------------------------------------------------------------------------------

procedure BlockHash(var State: TKeccakState; const Block);
type
  TIn64Array = Array[0..0] of Int64;
var
  i:  Integer;
begin
For i := 0 to Pred(State.BlockSize shr 3) do
  State.Sponge[i div 5,i mod 5] := State.Sponge[i div 5,i mod 5] xor TIn64Array(Block)[i];
Permute(State);
end;

//------------------------------------------------------------------------------

procedure Squeeze(var State: TKeccakState; var Buffer);
var
  BytesToSqueeze:  Int64;
begin
BytesToSqueeze := State.HashBits shr 3;
If BytesToSqueeze > State.BlockSize then
  while BytesToSqueeze > 0 do
    begin
      Move(State.Sponge,TByteArray(Buffer)[(State.HashBits shr 3) - BytesToSqueeze],Min(BytesToSqueeze,State.BlockSize));
      Permute(State);
      Dec(BytesToSqueeze,Min(BytesToSqueeze,State.BlockSize));
    end
else Move(State.Sponge,Buffer,BytesToSqueeze);
end;

//==============================================================================

procedure RectifyHashPointer(var Hash: TSHA3Hash);
begin
case Hash.HashSize of
  Keccak224:  Hash.HashPtr := Addr(Hash.KeccakHash_224);
  Keccak256:  Hash.HashPtr := Addr(Hash.KeccakHash_256);
  Keccak384:  Hash.HashPtr := Addr(Hash.KeccakHash_384);
  Keccak512:  Hash.HashPtr := Addr(Hash.KeccakHash_512);
  SHA3_224:   Hash.HashPtr := Addr(Hash.SHA3Hash_224);
  SHA3_256:   Hash.HashPtr := Addr(Hash.SHA3Hash_256);
  SHA3_384:   Hash.HashPtr := Addr(Hash.SHA3Hash_384);
  SHA3_512:   Hash.HashPtr := Addr(Hash.SHA3Hash_512);
  Keccak_b,
  SHAKE128,
  SHAKE256:;  // Do nothing.
else
  raise Exception.CreateFmt('RectifyHashPointer: Unknown hash size (%d)',[Integer(Hash.HashSize)]);
end;
end;

//------------------------------------------------------------------------------

procedure PrepareHash(State: TSHA3State; out Hash: TSHA3Hash);
begin
Hash.HashBits := State.HashBits;
Hash.HashSize := State.HashSize;
If Hash.HashSize in [Keccak_b,SHAKE128,SHAKE256] then
  Hash.HashPtr := AllocMem(Hash.HashBits shr 3)
else
  RectifyHashPointer(Hash);
end;

//==============================================================================

Function GetBlockSize(HashSize: TKeccakHashSize): LongWord;
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
  raise Exception.CreateFmt('GetBlockSize: Unknown hash size (%d).',[Integer(HashSize)]);
end;
end;

//------------------------------------------------------------------------------

Function InitialSHA3State(HashSize: TSHA3HashSize; HashBits: LongWord = 0): TSHA3State;
begin
Result.HashSize := HashSize;
case HashSize of
  Keccak224, SHA3_224:  Result.HashBits := 224;
  Keccak256, SHA3_256:  Result.HashBits := 256;
  Keccak384, SHA3_384:  Result.HashBits := 384;
  Keccak512, SHA3_512:  Result.HashBits := 512;
else
  If (HashBits and $7) <> 0 then
    raise Exception.Create('InitialSHA3State: HashBits must be divisible by 8.')
  else
    Result.HashBits := HashBits;
end;
Result.BlockSize := GetBlockSize(HashSize);
FillChar(Result.Sponge,SizeOf(Result.Sponge),0);
end;

//------------------------------------------------------------------------------

procedure CopySHA3Hash(Source: TSHA3Hash; var Destination: TSHA3Hash);
begin
Destination := Source;
If Source.HashSize in [Keccak_b,SHAKE128,SHAKE256] then
  begin
    Destination.HashPtr := AllocMem(Destination.HashBits shr 3);
    Move(Source.HashPtr^,Destination.HashPtr^,Destination.HashBits shr 3);
  end
else RectifyHashPointer(Destination);
end;

//------------------------------------------------------------------------------

procedure FinalizeSHA3Hash(var Hash: TSHA3Hash);
begin
If Hash.HashSize in [Keccak_b,SHAKE128,SHAKE256] then
  begin
    FreeMem(Hash.HashPtr,Hash.HashBits shr 3);
    Hash.HashPtr := nil;
  end;
end;

//==============================================================================

Function SHA3ToStr(Hash: TSHA3Hash): String;
var
  i:  Integer;
begin
RectifyHashPointer(Hash);
SetLength(Result,(Hash.HashBits shr 3) * 2);
For i := 0 to Pred(Hash.HashBits shr 3) do
  begin
    Result[(i * 2) + 1] := IntToHex(TByteArray(Hash.HashPtr^)[i],2)[1];
    Result[(i * 2) + 2] := IntToHex(TByteArray(Hash.HashPtr^)[i],2)[2];
  end;
end;

//------------------------------------------------------------------------------

Function StrToSHA3(HashSize: TSHA3HashSize; Str: String): TSHA3Hash;
var
  HashCharacters: Integer;
  i:              Integer;
begin
case HashSize of
  Keccak224, SHA3_224:  Result.HashBits := 224;
  Keccak256, SHA3_256:  Result.HashBits := 256;
  Keccak384, SHA3_384:  Result.HashBits := 384;
  Keccak512, SHA3_512:  Result.HashBits := 512;
  Keccak_b,
  SHAKE128,
  SHAKE256: begin
              Result.HashPtr := AllocMem(Length(Str) shr 1);
              Result.HashBits := (Length(Str) shr 1) shl 3;
            end;
else
  raise Exception.CreateFmt('StrToSHA3: Unknown source hash size (%d).',[Integer(HashSize)]);
end;
Result.HashSize := HashSize;
RectifyHashPointer(Result);
HashCharacters := Result.HashBits shr 2;
If Length(Str) < HashCharacters then
  Str := StringOfChar('0',HashCharacters - Length(Str)) + Str
else
  If Length(Str) > HashCharacters then
    Str := Copy(Str,Length(Str) - HashCharacters + 1,HashCharacters);
For i := 0 to Pred(Result.HashBits shr 3) do
  TByteArray(Result.HashPtr^)[i] := StrToInt('$' + Copy(Str,(i * 2) + 1,2));
end;

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
  CopySHA3Hash(Default,Result);
end;

//------------------------------------------------------------------------------

Function SameSHA3(A,B: TSHA3Hash): Boolean;
var
  i:  Integer;
begin
RectifyHashPointer(A);
RectifyHashPointer(B);
If (A.HashBits = B.HashBits) and (A.HashSize = B.HashSize) then
  begin
    Result := True;
    For i := 0 to Pred(A.HashBits shr 3) do
      If TByteArray(A.HashPtr^)[i] <> TByteArray(B.HashPtr^)[i] then
        begin
          Result := False;
          Break;
        end;
  end
else Result := False;
end;

//==============================================================================

procedure BufferSHA3(var State: TSHA3State; const Buffer; Size: TSize);
var
  i:  Integer;
begin
If (Size mod State.BlockSize) = 0 then
  begin
    For i := 0 to Pred(Size div State.BlockSize) do
      BlockHash(State,TByteArray(Buffer)[TSize(i) * State.BlockSize]);
  end
else raise Exception.CreateFmt('BufferSHA3: Buffer size is not divisible by %d.',[State.BlockSize]);
end;

//------------------------------------------------------------------------------

Function LastBufferSHA3(State: TSHA3State; const Buffer; Size: TSize): TSHA3Hash;
var
  FullBlocks:     LongWord;
  LastBlockSize:  LongWord;
  HelpBlocks:     LongWord;
  HelpBlocksBuff: Pointer;
begin
FullBlocks := Size div State.BlockSize;
If FullBlocks > 0 then BufferSHA3(State,Buffer,FullBlocks * State.BlockSize);
LastBlockSize := Size - TSize(FullBlocks * State.BlockSize);
HelpBlocks := Ceil((LastBlockSize + 1) / State.BlockSize);
HelpBlocksBuff := AllocMem(HelpBlocks * State.BlockSize);
try
  Move(TByteArray(Buffer)[FullBlocks * State.BlockSize],HelpBlocksBuff^,LastBlockSize);
  case State.HashSize of
    Keccak224..Keccak_b:  TByteArray(HelpBlocksBuff^)[LastBlockSize] := $01;
     SHA3_224..SHA3_512:  TByteArray(HelpBlocksBuff^)[LastBlockSize] := $06;
     SHAKE128..SHAKE256:  TByteArray(HelpBlocksBuff^)[LastBlockSize] := $1F;
  else
    raise Exception.CreateFmt('LastBufferSHA3: Unknown hash size (%d)',[Integer(State.HashSize)]);
  end;
  TByteArray(HelpBlocksBuff^)[Pred(HelpBlocks * State.BlockSize)] := TByteArray(HelpBlocksBuff^)[Pred(HelpBlocks * State.BlockSize)] xor $80;
  BufferSHA3(State,HelpBlocksBuff^,HelpBlocks * State.BlockSize);
finally
  FreeMem(HelpBlocksBuff,HelpBlocks * State.BlockSize);
end;
PrepareHash(State,Result);
Squeeze(State,Result.HashPtr^);
end;

//==============================================================================

Function BufferSHA3(HashSize: TSHA3HashSize; const Buffer; Size: TSize; HashBits: LongWord = 0): TSHA3Hash;
begin
Result := LastBufferSHA3(InitialSHA3State(HashSize,HashBits),Buffer,Size);
end;

//==============================================================================

Function AnsiStringSHA3(HashSize: TSHA3HashSize; const Str: AnsiString; HashBits: LongWord = 0): TSHA3Hash;
{$IFDEF UseStringStream}
var
  StringStream: TStringStream;
begin
StringStream := TStringStream.Create(Str);
try
  Result := StreamSHA3(HashSize,StringStream,-1,HashBits);
finally
  StringStream.Free;
end;
end;
{$ELSE}
begin
Result := BufferSHA3(HashSize,PAnsiChar(Str)^,Length(Str) * SizeOf(AnsiChar),HashBits);
end;
{$ENDIF}

//------------------------------------------------------------------------------

Function WideStringSHA3(HashSize: TSHA3HashSize; const Str: WideString; HashBits: LongWord = 0): TSHA3Hash;
{$IFDEF UseStringStream}
var
  StringStream: TStringStream;
begin
StringStream := TStringStream.Create(Str);
try
  Result := StreamSHA3(HashSize,StringStream,-1,HashBits);
finally
  StringStream.Free;
end;
end;
{$ELSE}
begin
Result := BufferSHA3(HashSize,PWideChar(Str)^,Length(Str) * SizeOf(WideChar),HashBits);
end;
{$ENDIF}

//------------------------------------------------------------------------------

Function StringSHA3(HashSize: TSHA3HashSize; const Str: String; HashBits: LongWord = 0): TSHA3Hash;
{$IFDEF UseStringStream}
var
  StringStream: TStringStream;
begin
StringStream := TStringStream.Create(Str);
try
  Result := StreamSHA3(HashSize,StringStream,-1,HashBits);
finally
  StringStream.Free;
end;
end;
{$ELSE}
begin
Result := BufferSHA3(HashSize,PChar(Str)^,Length(Str) * SizeOf(Char),HashBits);
end;
{$ENDIF}

//==============================================================================

Function StreamSHA3(HashSize: TSHA3HashSize; Stream: TStream; Count: Int64 = -1; HashBits: LongWord = 0): TSHA3Hash;
var
  Buffer:     Pointer;
  BytesRead:  TSize;
  State:      TSHA3State;
  BufferSize: LongWord;
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

Function FileSHA3(HashSize: TSHA3HashSize; const FileName: String; HashBits: LongWord = 0): TSHA3Hash;
var
  FileStream: TFileStream;
begin
FileStream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
try
  Result := StreamSHA3(HashSize,FileStream,-1,HashBits);
finally
  FileStream.Free;
end;
end;

end.

