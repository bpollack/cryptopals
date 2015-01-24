! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.
USING: base64 grouping kernel math math.parser sequences 
strings ;

IN: cryptopals

: hex>bytes ( s -- bytes )
    2 <groups> [ hex> ] B{ } map-as ;

: bytes>hex ( bytes -- s )
    [ >hex ] { } map-as concat ;

: hex>base64 ( s -- s )
    hex>bytes >base64 >string ;

: xor-hexes ( seq1 seq2 -- seq1^seq2 )
    [ hex>bytes ] bi@ [ bitxor ] 2map ;
