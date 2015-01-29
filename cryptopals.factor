! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.

USING: arrays base64 combinators.short-circuit circular
grouping kernel locals math math.order math.parser sequences 
sets strings ;

IN: cryptopals

: hex>bytes ( s -- bytes )
    2 <groups> [ hex> ] B{ } map-as ;

: bytes>hex ( bytes -- s )
    [ >hex ] { } map-as concat ;

: hex>base64 ( s -- s )
    hex>bytes >base64 >string ;

: xor-bytes ( seq1 seq2 -- seq1^seq2 )
    <circular> [ bitxor ] 2map ;

: xor-hexes ( seq1 seq2 -- seq1^seq2 )
    [ hex>bytes ] bi@ xor-bytes ;

: likely-char? ( ch -- f )
    {
        [ CHAR: A CHAR: Z between? ]
        [ CHAR: a CHAR: z between? ]
        [ CHAR: 0 CHAR: 9 between? ]
        [ HS{ CHAR: , CHAR: . CHAR: \s CHAR: ? CHAR: ! } in? ]
    } 1|| ;

: likely-chars ( string -- count )
    0 [ likely-char? [ 1 + ] when ] reduce ;

: text-likeliness ( string -- rating )
    [ likely-chars ] [ length ] bi / >float ;

: likely-text? ( string -- f )
    text-likeliness 0.99 > ;

: likely-key? ( bytes key -- f )
    xor-bytes likely-text? ;

:: find-probable-keys ( hex -- keys )
    hex hex>bytes :> bytes
    256 iota [ >string 1array bytes likely-key? ] filter ;
