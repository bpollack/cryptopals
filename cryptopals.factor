! Copyright (C) 2015 Benjamin Pollack.
! See http://factorcode.org/license.txt for BSD license.

USING: arrays ascii assocs assocs.extras base64 combinators.short-circuit circular
formatting fry grouping kernel locals math math.bitwise
math.combinatorics math.extras math.order math.parser math.ranges math.statistics sequences
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

: english-distribution ( -- dist )
    H{
        { CHAR: a  8.167 }
        { CHAR: b  1.492 }
        { CHAR: c  2.782 }
        { CHAR: d  4.253 }
        { CHAR: e 12.702 }
        { CHAR: f  2.228 }
        { CHAR: g  2.015 }
        { CHAR: h  6.094 }
        { CHAR: i  6.966 }
        { CHAR: j  0.153 }
        { CHAR: k  0.772 }
        { CHAR: l  4.025 }
        { CHAR: m  2.406 }
        { CHAR: n  6.749 }
        { CHAR: o  7.507 }
        { CHAR: p  1.929 }
        { CHAR: q  0.095 }
        { CHAR: r  5.987 }
        { CHAR: s  6.327 }
        { CHAR: t  9.056 }
        { CHAR: u  2.758 }
        { CHAR: v  0.978 }
        { CHAR: w  2.360 }
        { CHAR: x  0.150 }
        { CHAR: y  1.974 }
        { CHAR: z  0.074 }
    } ;

: bad-text-likeliness ( string -- rating )
    [ likely-char? ] count* ;

: map-alphabet ( ... quot: ( ... elt -- ... newelt ) -- ... newseq )
    CHAR: a CHAR: z [a,b] swap map ; inline

: text-likeliness ( string -- rating )
    dup bad-text-likeliness swap
    >lower histogram '[ _ at [ 0 ] unless* ] map-alphabet
    english-distribution '[ _ at [ 0 ] unless* ] map-alphabet
    chi2 + 2 / ;

: likely-text? ( string -- f )
    text-likeliness 0.95 > ;

: likely-key? ( bytes key -- f )
    xor-bytes likely-text? ;

: likely-keys ( bytes -- keys )
    256 iota [
        1array over likely-key?
    ] filter nip ;

: likeliest-key ( bytes -- key )
    256 iota [
        1array over xor-bytes text-likeliness
    ] map nip <enum> sort-values first first ;

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
