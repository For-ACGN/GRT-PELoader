IFDEF _WIN32
.model tiny
ENDIF

.code

IFDEF _WIN32
  _Argument_Stub@0 proc
  db 0D7h, 012h, 0B1h, 045h
  db 0F6h, 07Bh, 08Eh, 0C8h
  db 099h, 0B3h, 0F7h, 052h
  db 0F5h, 02Bh, 0EAh, 088h
  db 011h, 021h, 0C8h, 006h
  db 0A1h, 021h, 0FBh, 031h
  db 0B1h, 050h, 0A0h, 0E0h
  db 044h, 078h, 08Bh, 051h
  db 0A9h, 039h, 073h, 017h
  db 006h, 000h, 000h, 000h
  db 040h, 000h, 000h, 000h
  db 02Ch, 016h, 0B1h, 045h
  db 009h, 07Bh, 071h, 0C8h
  db 08Eh, 0A4h, 0F7h, 052h
  db 081h, 03Ah, 0FCh, 08Fh
  db 03Ah, 006h, 088h, 008h
  db 0B9h, 06Ah, 0E6h, 02Ch
  db 0F4h, 05Dh, 0ECh, 0F3h
  db 051h, 03Fh, 09Ah, 052h
  db 0D6h, 015h, 085h, 041h
  db 0F2h, 07Bh, 08Eh, 0C8h
  db 099h, 0B3h, 0F7h, 056h
  db 0F1h, 02Bh, 0EAh, 088h
  db 011h, 021h, 0C8h, 002h
  db 0A5h, 021h, 0FBh, 031h
  db 0B1h, 050h, 0A0h, 0E1h
  db 045h, 078h, 08Bh, 050h
  _Argument_Stub@0 endp
ELSE
  Argument_Stub proc
  db 084h, 09Fh, 041h, 0AEh
  db 030h, 063h, 024h, 0EEh
  db 0F7h, 00Bh, 059h, 017h
  db 03Fh, 010h, 035h, 070h
  db 018h, 045h, 0EFh, 0A1h
  db 0DEh, 0F8h, 0DBh, 07Bh
  db 07Bh, 06Eh, 05Eh, 041h
  db 03Bh, 0C0h, 076h, 0A3h
  db 0BDh, 063h, 01Eh, 0F9h
  db 006h, 000h, 000h, 000h
  db 04Ch, 000h, 000h, 000h
  db 07Fh, 09Bh, 041h, 0AEh
  db 0CFh, 063h, 0DBh, 0EEh
  db 0E0h, 01Ch, 059h, 017h
  db 04Bh, 001h, 023h, 077h
  db 033h, 062h, 0A1h, 0A3h
  db 0C4h, 0B3h, 0C6h, 066h
  db 03Eh, 063h, 012h, 052h
  db 02Eh, 087h, 067h, 0A0h
  db 085h, 098h, 075h, 0A6h
  db 038h, 063h, 024h, 0EEh
  db 0F7h, 00Bh, 059h, 017h
  db 03Fh, 010h, 035h, 078h
  db 010h, 045h, 0EFh, 0A1h
  db 0DEh, 0F8h, 0DBh, 07Bh
  db 07Bh, 06Eh, 05Eh, 049h
  db 033h, 0C0h, 076h, 0A3h
  db 084h, 09Fh, 041h, 0AEh
  db 030h, 063h, 024h, 0EFh
  db 0F6h, 00Bh, 059h, 016h
  Argument_Stub endp
ENDIF

end
