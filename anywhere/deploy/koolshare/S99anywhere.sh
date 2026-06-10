#!/bin/sh

alias echo_date='echo $(date +%Y年%m月%d日\ %X)'
source /koolshare/scripts/base.sh

_LOG "[软件中心]-[S99anywhere.sh]: 启动anywhere！"
(sleep 30; /jffs/anywhere/anywhere.sh $1) &