! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.

USING: arrays base64 combinators.short-circuit circular
formatting fry grouping kernel locals math math.bitwise
math.order math.parser math.ranges math.statistics sequences
sequences.extras sets strings ;

IN: cryptopals

: hex>bytes ( s -- bytes )
    2 <groups> [ hex> ] B{ } map-as ;

: bytes>hex ( bytes -- s )
    [ "%02x" sprintf ] { } map-as concat ;

: hex>base64 ( s -- s )
    hex>bytes >base64 >string ;

: sorted-seqs ( seq1 seq2 -- longer-seq shorter-seq )
    2dup [ length ] bi@ =
    [ 2array [ longest ] [ shortest ] bi ] unless ;

: xor-bytes ( seq1 seq2 -- seq1^seq2 )
    sorted-seqs <circular> '[ _ nth bitxor ] map-index ;

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
    [ likely-char? 1 0 ? ] map-sum ;

: text-likeliness ( string -- rating )
    [ likely-chars ] [ length ] bi / ;

: likely-text? ( string -- f )
    text-likeliness 0.95 > ;

: likely-key? ( bytes key -- f )
    xor-bytes likely-text? ;

:: likely-keys ( bytes -- keys )
    256 iota [| key |
        bytes key 1array likely-key?
    ] filter ;

:: likely-decryptions ( hex -- decryptions )
    hex hex>bytes :> bytes
    bytes likely-keys [| key |
        bytes key 1array xor-bytes >string
    ] map ;

: hamming-distance ( a b -- distance )
    [ bitxor ] 2map [ bit-count ] map-sum ;

:: normalized-distances ( bytes -- distances )
    2 bytes length 40 min [a,b]
    [| size |
        bytes size <groups>
        [ first ] [ second ] bi hamming-distance size /
    ] map ;

: likely-keysizes ( bytes -- sizes )
    normalized-distances dup
    { 0 1 2 } kth-smallests '[ _ in? ] find-all
    [ first ] map ;
