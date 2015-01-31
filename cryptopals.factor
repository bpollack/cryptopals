! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.

USING: arrays assocs base64 combinators.short-circuit circular
formatting fry grouping kernel locals math math.bitwise
math.combinatorics math.order math.parser math.ranges math.statistics sequences
sequences.extras sets sorting strings ;

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
        [ ",. \t\n\r?!" in? ]
    } 1|| ;

: text-likeliness ( string -- rating )
    [ likely-char? ] count* ;

: likely-text? ( string -- f )
    text-likeliness 0.95 > ;

: likely-key? ( bytes key -- f )
    xor-bytes likely-text? ;

:: likely-keys ( bytes -- keys )
    256 iota [| key |
        bytes key 1array likely-key?
    ] filter ;

: likeliest-key ( bytes -- key )
    256 iota swap '[
        1array _ xor-bytes text-likeliness
    ] map <enum> sort-values last first ;

: likeliest-decryption ( bytes -- decryption )
    dup likeliest-key 1array xor-bytes >string ;

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
        0 4 bytes size <groups> <slice> 2 [
            first2 hamming-distance size /
        ] map-combinations mean
    ] map ;

: keysize-distance ( bytes -- sizes )
    normalized-distances <enum> sort-values [
        first2 [ 1 + ] dip 2array
    ] map ;

:: likeliest-repeating-key ( bytes keysize -- key )
    bytes keysize <groups> :> chunks
    keysize iota [| offset |
        chunks [| chunk |
            chunk length offset > [ offset chunk nth ] [ 0 ] if
        ] map likeliest-key
    ] map ;
