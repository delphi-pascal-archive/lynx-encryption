{------------------------------------ LYNX -------------------------------------

Algorithme de chiffrement par bloc Lynx, cette unité contient les fonctions de
base pour créer une clef, chiffrer et déchiffrer un bloc, et propose une API
décente pour utiliser cet algorithme en mode flux CFB (Cipher FeedBack).

Auteur : Bacterius. Cet header ne peut être retiré de cette unité, ni altéré.  }

unit Lynx;

interface

uses Windows, SysUtils, Classes;

type
 { A block structure, as an eight-byte array. Use casting extensively ! }
 TBlock = array [$0..$7] of Byte;
 PBlock = ^TBlock;
 { A key structure. Contains the 256-bit subkey array, and s-box/inverse-box. }
 TSubkeys = record
  Subkey: array [$0..$3] of TBlock;
  SBox, IBox: array [Byte] of Byte;
 end;
 TLynxCallback = function (BlockIndex, BlockCount: Longword): Boolean;

{ Key schedule of the cipher - the subkeys and the secret s-box are generated }
procedure KeySchedule(const Key; const Keylen: Byte; var Subkeys: TSubkeys);
{ The encryption algorithm, encrypting a 64-bit block given some key }
procedure EncryptBlock(var Block: TBlock; const Key: TSubkeys);
{ The inverse of the encryption algorithm that recovers plaintext }
procedure DecryptBlock(var Block: TBlock; const Key: TSubkeys);
{ Encryption in CFB mode of a buffer }
procedure Encrypt(const Buffer; Size: Longword; const Key: TSubkeys; IV: Int64; const Callback: TLynxCallback = nil);
{ Decryption in CFB mode of a buffer }
procedure Decrypt(const Buffer; Size: Longword; const Key: TSubkeys; IV: Int64; const Callback: TLynxCallback = nil);
{ En/Decryption in CFB mode of a file }
function EncryptFile(const FilePath: String; const Key: TSubkeys; IV: Int64; const DoDecrypt: Boolean; const Callback: TLynxCallback = nil): Boolean;

implementation

const
 { Magic constants - hex value of 1/Pi, 1/Phi, 1/Sqrt(2) and 1/Sqrt(7) }
 MAGIC: array [$0..$3] of Int64 = ($517CC1B727220A95, $9E3779B97F4A7C15,
                                   $B504F333F9DE6484, $60C2479A9FDF9A22);

function ROL(const A: Int64; const B: Longword): Int64;
begin
 Result := (A shl B) or (A shr ($40 - B));
end;

procedure Swap(var A, B: Int64);
Var
 C: Int64;
begin
 C := A;
 A := B;
 B := C;
end;

{ Key schedule of the cipher - the subkeys and the secret s-box are generated }
procedure KeySchedule(const Key; const Keylen: Byte; var Subkeys: TSubkeys);
Var
 P: PByte;
 E: Pointer;
 I: Longword;
 X, C: Byte;
begin
 with Subkeys do
  begin
   { Initialize the S-box with default values (0, 1, 2, 3, 4, ...) }
   for I := $00 to $FF do SBox[I] := I;
   P := @Key;
   E := Ptr(Longword(@Key) + Keylen);

   X := P^;

   { Generate the substitution box }
   for I := $00 to $FF do
    begin
     { Increment and rotate }
     Inc(X, (P^ + SBOX[X] + SBOX[P^] + SBOX[I]) xor SBOX[KeyLen]);
     X := (X shl $3) or (X shr $5);

     { Swap }
     C := SBOX[I];
     SBOX[I] := SBOX[X];
     SBOX[X] := C;

     { "Wrap around" the key }
     Inc(P);
     if P = E then P := @Key;
    end;

   { Now we're going to need the inverse S-box when decrypting ... neat trick }
   for I := $00 to $FF do IBox[SBox[I]] := I;

   { Generate the subkeys using a nonlinear algorithm ...
     ... First, load "magic" constants into the subkeys. }
   Move(MAGIC, Subkey, SizeOf(MAGIC));

   { Now use every single bit of information in the key to alter the subkeys ...
     ... each byte of the original key is used to rotate or mix the subkeys }
   P := @Key;
   while P <> E do
    begin
     { Rotate first two subkeys using the key byte }
     ROL(Int64(Subkey[$0]), (P^ shr $4) and $F);
     ROL(Int64(Subkey[$1]), (P^       ) and $F);

     { Increment the last two subkeys using the first two subkeys }
     Inc(Int64(Subkey[$2]), Int64(Subkey[$0]));
     Inc(Int64(Subkey[$3]), Int64(Subkey[$1]));

     { Rotate last two subkeys using the substitution of the key byte }
     ROL(Int64(Subkey[$2]), (SBox[P^] shr $4) and $F);
     ROL(Int64(Subkey[$3]), (SBox[P^]       ) and $F);

     { Swap first two and last two subkeys }
     Swap(Int64(Subkey[$0]), Int64(Subkey[$2]));
     Swap(Int64(Subkey[$1]), Int64(Subkey[$3]));
     Inc(P);
    end;
  end;
end;

{ The encryption algorithm, encrypting a 64-bit block given some key }
procedure EncryptBlock(var Block: TBlock; const Key: TSubkeys);
begin
 with Key do
  begin
   { Add the first subkey to the block }
   Inc(Block[$0], Subkey[$0][$0]);
   Inc(Block[$1], Subkey[$0][$1]);
   Inc(Block[$2], Subkey[$0][$2]);
   Inc(Block[$3], Subkey[$0][$3]);
   Inc(Block[$4], Subkey[$0][$4]);
   Inc(Block[$5], Subkey[$0][$5]);
   Inc(Block[$6], Subkey[$0][$6]);
   Inc(Block[$7], Subkey[$0][$7]);

   { Use substitution rule A }
   Block[$7] := SBox[Block[$0] xor Block[$1] xor Block[$2] xor Block[$3]
                xor Block[$4] xor Block[$5] xor Block[$6] xor Block[$7]];
   Block[$6] := SBox[Block[$6] xor Block[$7]];
   Block[$5] := SBox[Block[$5] xor Block[$6]];
   Block[$4] := SBox[Block[$4] xor Block[$5]];
   Block[$3] := SBox[Block[$3] xor Block[$4]];
   Block[$2] := SBox[Block[$2] xor Block[$3]];
   Block[$1] := SBox[Block[$1] xor Block[$2]];
   Block[$0] := SBox[Block[$0] xor Block[$1]];

   { Add the second subkey to the block }
   Inc(Block[$0], Subkey[$1][$0]);
   Inc(Block[$1], Subkey[$1][$1]);
   Inc(Block[$2], Subkey[$1][$2]);
   Inc(Block[$3], Subkey[$1][$3]);
   Inc(Block[$4], Subkey[$1][$4]);
   Inc(Block[$5], Subkey[$1][$5]);
   Inc(Block[$6], Subkey[$1][$6]);
   Inc(Block[$7], Subkey[$1][$7]);

   { Use substitution rule B }
   Block[$0] := SBox[Block[$0] xor Block[$1] xor Block[$2] xor Block[$3]
                xor Block[$4] xor Block[$5] xor Block[$6] xor Block[$7]];
   Block[$1] := SBox[Block[$1] xor Block[$0]];
   Block[$2] := SBox[Block[$2] xor Block[$1]];
   Block[$3] := SBox[Block[$3] xor Block[$2]];
   Block[$4] := SBox[Block[$4] xor Block[$3]];
   Block[$5] := SBox[Block[$5] xor Block[$4]];
   Block[$6] := SBox[Block[$6] xor Block[$5]];
   Block[$7] := SBox[Block[$7] xor Block[$6]];

   { Add the third subkey to the block }
   Inc(Block[$0], Subkey[$2][$0]);
   Inc(Block[$1], Subkey[$2][$1]);
   Inc(Block[$2], Subkey[$2][$2]);
   Inc(Block[$3], Subkey[$2][$3]);
   Inc(Block[$4], Subkey[$2][$4]);
   Inc(Block[$5], Subkey[$2][$5]);
   Inc(Block[$6], Subkey[$2][$6]);
   Inc(Block[$7], Subkey[$2][$7]);

   { Use substitution rule C }
   Int64(Block) := (Int64(Block) shl $4) or (Int64(Block) shr $3C);
   Block[$0] := SBox[Block[$0]];
   Block[$1] := SBox[Block[$1]];
   Block[$2] := SBox[Block[$2]];
   Block[$3] := SBox[Block[$3]];
   Block[$4] := SBox[Block[$4]];
   Block[$5] := SBox[Block[$5]];
   Block[$6] := SBox[Block[$6]];
   Block[$7] := SBox[Block[$7]];

   { Add the fourth and last subkey to the block }
   Inc(Block[$0], Subkey[$3][$0]);
   Inc(Block[$1], Subkey[$3][$1]);
   Inc(Block[$2], Subkey[$3][$2]);
   Inc(Block[$3], Subkey[$3][$3]);
   Inc(Block[$4], Subkey[$3][$4]);
   Inc(Block[$5], Subkey[$3][$5]);
   Inc(Block[$6], Subkey[$3][$6]);
   Inc(Block[$7], Subkey[$3][$7]);
  end;
end;

procedure DecryptBlock(var Block: TBlock; const Key: TSubkeys);
begin
 with Key do
  begin
   { Substract the last subkey to the block }
   Dec(Block[$0], Subkey[$3][$0]);
   Dec(Block[$1], Subkey[$3][$1]);
   Dec(Block[$2], Subkey[$3][$2]);
   Dec(Block[$3], Subkey[$3][$3]);
   Dec(Block[$4], Subkey[$3][$4]);
   Dec(Block[$5], Subkey[$3][$5]);
   Dec(Block[$6], Subkey[$3][$6]);
   Dec(Block[$7], Subkey[$3][$7]);

   { Use inverse substitution rule C }
   Block[$0] := IBox[Block[$0]];
   Block[$1] := IBox[Block[$1]];
   Block[$2] := IBox[Block[$2]];
   Block[$3] := IBox[Block[$3]];
   Block[$4] := IBox[Block[$4]];
   Block[$5] := IBox[Block[$5]];
   Block[$6] := IBox[Block[$6]];
   Block[$7] := IBox[Block[$7]];
   Int64(Block) := (Int64(Block) shr $4) or (Int64(Block) shl $3C);

   { Substract the third subkey to the block }
   Dec(Block[$0], Subkey[$2][$0]);
   Dec(Block[$1], Subkey[$2][$1]);
   Dec(Block[$2], Subkey[$2][$2]);
   Dec(Block[$3], Subkey[$2][$3]);
   Dec(Block[$4], Subkey[$2][$4]);
   Dec(Block[$5], Subkey[$2][$5]);
   Dec(Block[$6], Subkey[$2][$6]);
   Dec(Block[$7], Subkey[$2][$7]);

   { Use inverse substitution rule B }
   Block[$7] := IBox[Block[$7]] xor Block[$6];
   Block[$6] := IBox[Block[$6]] xor Block[$5];
   Block[$5] := IBox[Block[$5]] xor Block[$4];
   Block[$4] := IBox[Block[$4]] xor Block[$3];
   Block[$3] := IBox[Block[$3]] xor Block[$2];
   Block[$2] := IBox[Block[$2]] xor Block[$1];
   Block[$1] := IBox[Block[$1]] xor Block[$0];
   Block[$0] := IBox[Block[$0]] xor Block[$1] xor Block[$2] xor Block[$3]
                  xor Block[$4] xor Block[$5] xor Block[$6] xor Block[$7];

   { Substract the second subkey to the block }
   Dec(Block[$0], Subkey[$1][$0]);
   Dec(Block[$1], Subkey[$1][$1]);
   Dec(Block[$2], Subkey[$1][$2]);
   Dec(Block[$3], Subkey[$1][$3]);
   Dec(Block[$4], Subkey[$1][$4]);
   Dec(Block[$5], Subkey[$1][$5]);
   Dec(Block[$6], Subkey[$1][$6]);
   Dec(Block[$7], Subkey[$1][$7]);

   { Use inverse substitution rule A }
   Block[$0] := IBox[Block[$0]] xor Block[$1];
   Block[$1] := IBox[Block[$1]] xor Block[$2];
   Block[$2] := IBox[Block[$2]] xor Block[$3];
   Block[$3] := IBox[Block[$3]] xor Block[$4];
   Block[$4] := IBox[Block[$4]] xor Block[$5];
   Block[$5] := IBox[Block[$5]] xor Block[$6];
   Block[$6] := IBox[Block[$6]] xor Block[$7];
   Block[$7] := IBox[Block[$7]] xor Block[$0] xor Block[$1] xor Block[$2]
                  xor Block[$3] xor Block[$4] xor Block[$5] xor Block[$6];

   { Substract the first subkey to the block }
   Dec(Block[$0], Subkey[$0][$0]);
   Dec(Block[$1], Subkey[$0][$1]);
   Dec(Block[$2], Subkey[$0][$2]);
   Dec(Block[$3], Subkey[$0][$3]);
   Dec(Block[$4], Subkey[$0][$4]);
   Dec(Block[$5], Subkey[$0][$5]);
   Dec(Block[$6], Subkey[$0][$6]);
   Dec(Block[$7], Subkey[$0][$7]);
  end;
end;

{ Encryption in CFB mode of a buffer }
procedure Encrypt(const Buffer; Size: Longword; const Key: TSubkeys; IV: Int64; const Callback: TLynxCallback = nil);
Var
 P: PBlock;
 E: Pointer;
 B: TBlock;
 N, C: Longword;
begin
 P := @Buffer;
 E := Ptr(Longword(P) + Size - (Size and $7));
 N := Size shr $3;
 C := $0;
 Size := Size and $7;

 while P <> E do
  begin
   EncryptBlock(TBlock(IV), Key);
   Int64(P^) := Int64(P^) xor IV;
   IV := Int64(P^);
   Inc(P);
   Inc(C);
   if Assigned(Callback) then if Callback(C, N) then Exit;
  end;

 if Size > $0 then
  begin
   EncryptBlock(TBlock(IV), Key);
   Move(P^, B, Size);
   Int64(B) := Int64(B) xor IV;
   Move(B, P^, Size);
  end;

 if Assigned(Callback) then Callback(N, N);
end;

{ Decryption in CFB mode of a buffer }
procedure Decrypt(const Buffer; Size: Longword; const Key: TSubkeys; IV: Int64; const Callback: TLynxCallback = nil);
Var
 P: PBlock;
 E: Pointer;
 B: TBlock;
 N, C: Longword;
begin
 P := @Buffer;
 E := Ptr(Longword(P) + Size - (Size and $7));
 N := Size shr $3;
 C := $0;
 Size := Size and $7;

 while P <> E do
  begin
   EncryptBlock(TBlock(IV), Key);
   B := P^;
   Int64(P^) := Int64(P^) xor IV;
   IV := Int64(B);
   Inc(P);
   Inc(C);
   if Assigned(Callback) then if Callback(C, N) then Exit;
  end;

 if Size > $0 then
  begin
   EncryptBlock(TBlock(IV), Key);
   Move(P^, B, Size);
   Int64(B) := Int64(B) xor IV;
   Move(B, P^, Size);
  end;

 if Assigned(Callback) then Callback(N, N);
end;

{ Encryption in CFB mode of a file }
function EncryptFile(const FilePath: String; const Key: TSubkeys; IV: Int64; const DoDecrypt: Boolean; const Callback: TLynxCallback = nil): Boolean;
Var
 H, M: Longword;
 P: Pointer;
begin
 Result := False;

 H := CreateFile(PChar(FilePath), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE,
                 nil, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL or FILE_FLAG_SEQUENTIAL_SCAN, 0);

 if H <> INVALID_HANDLE_VALUE then
  begin
   if GetFileSize(H, nil) = 0 then CloseHandle(H) else
    begin
     try
      M := CreateFileMapping(H, nil, PAGE_READWRITE, 0, 0, nil);
      try
       if M = 0 then Exit;
       P := MapViewOfFile(M, FILE_MAP_ALL_ACCESS, 0, 0, 0);
       try
        if P <> nil then
         case DoDecrypt of
          False: Encrypt(P^, GetFileSize(H, nil), Key, IV, Callback);
          True: Decrypt(P^, GetFileSize(H, nil), Key, IV, Callback);
         end;
       finally
       UnmapViewOfFile(P);
       end;
      finally
       CloseHandle(M);
      end;
     finally
      CloseHandle(H);
      Result := True;
     end;
    end;
  end;
end;

end.
