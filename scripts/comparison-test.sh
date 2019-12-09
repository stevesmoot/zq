#!/bin/bash
set -e

zlog=~/Downloads/sampledata/wrccdc/zeek-logs/ssl.log
bzlog=~/Downloads/sampledata/wrccdc/zeek-logs/ssl.bzson
jlog=~/Downloads/sampledata/wrccdc/streaming-json-zeek-logs/ssl.log

time=$(which time)

declare -a zqls=(
    "*"
    "cut ts, id"
    "count()"
    "count() by cipher"
    "id.resp_h=52.85.83.116"
)
declare -a jqs=(
    '.'
    '. | { ts, orig_h: .["id.orig_h"], orig_p: .["id.orig_p"], resp_h: .["id.resp_h"], resp_p: .["id.resp_p"] }'
    '. | length'
    'group_by(.cipher)[] | length as $l | .[0] | .count = $l | {count, cipher}'
    '. | select(.["id.resp_h"]=="52.85.83.116")'
)
declare -a jqflags=(
    ''
    ''
    '-s'
    '-s'
    ''
)
declare -a zcuts=(
    ''
    'ts id.orig_h id.orig_p id.resp_h id.resp_p'
    'NONE'
    'NONE'
    'NONE'
)



for (( n=0; n<"${#zqls[@]}"; n++ ))
do
    zql=${zqls[$n]}
    echo ------------
    echo "- zq: $zql"
    echo "  zeek->zeek"
    $time  zq "$zql" - < $zlog > /dev/null
    echo "  bzson->zeek"
    $time  zq -i bzson "$zql" - < $bzlog > /dev/null
    echo "  zeek->ndjson"
    $time  zq -f ndjson "$zql" - < $zlog > /dev/null
    echo "  ndjson->ndjson"
    $time  zq -f ndjson "$zql" - < $jlog > /dev/null

    zcut=${zcuts[$n]}
    if [[ $zcut != "NONE" ]]; then
        echo "- zeek-cut: $zcut"
        $time  zeek-cut $zcut < $zlog > /dev/null
    fi

    jq=${jqs[$n]}
    jqflag=${jqflags[$n]}
    echo "- jq: $jq $jqflags"
    $time  jq $jqflag "$jq" < $jlog > /dev/null

    echo
done


