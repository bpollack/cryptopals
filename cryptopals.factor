! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.

USING: base64 combinators.short-circuit grouping kernel math
math.order math.parser sequences sets strings ;

IN: cryptopals

: hex>bytes ( s -- bytes )
    2 <groups> [ hex> ] B{ } map-as ;

: bytes>hex ( bytes -- s )
    [ >hex ] { } map-as concat ;

: hex>base64 ( s -- s )
    hex>bytes >base64 >string ;

: xor-hexes ( seq1 seq2 -- seq1^seq2 )
    [ hex>bytes ] bi@ [ bitxor ] 2map ;

: likely-char? ( ch -- f )
    {
        [ CHAR: A CHAR: Z between? ]
        [ CHAR: a CHAR: z between? ]
        [ CHAR: 0 CHAR: 9 between? ]
        [ HS{ CHAR: , CHAR: . CHAR: \s CHAR: ? CHAR: ! } in? ]
    } 1|| ;

: likely-chars ( s -- count )
    0 [ likely-char? [ 1 + ] when ] reduce ;

: text-likeliness ( s -- rating )
    [ likely-chars ] [ length ] bi / >float ;

: likely-text? ( s -- f )
    [ likely-char? ] all? ;
