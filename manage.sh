#!/bin/bash

SCRIPT_NAME="port_scanner_mcp.py"
PORT=9090

start() {
    echo "🚀 启动端口扫描服务..."
    python $SCRIPT_NAME &
    echo "✅ 服务已启动"
    sleep 2
    status
}

stop() {
    echo "⏹️  停止端口扫描服务..."
    pkill -f $SCRIPT_NAME
    sleep 1
    
    # 确保端口释放
    if lsof -i:$PORT > /dev/null 2>&1; then
        echo "⚠️  端口仍被占用，强制杀死进程..."
        kill -9 $(lsof -t -i:$PORT)
    fi
    
    echo "✅ 服务已停止"
}

restart() {
    echo "🔄 重启端口扫描服务..."
    stop
    sleep 2
    start
}

status() {
    if pgrep -f $SCRIPT_NAME > /dev/null; then
        PID=$(pgrep -f $SCRIPT_NAME)
        echo "✅ 服务正在运行 (PID: $PID)"
        
        if lsof -i:$PORT > /dev/null 2>&1; then
            echo "✅ 端口 $PORT 正在监听"
            echo "🌐 访问地址: http://$(hostname -I | awk '{print $1}'):$PORT"
        fi
    else
        echo "❌ 服务未运行"
    fi
}

logs() {
    echo "📋 查看日志（Ctrl+C 退出）..."
    tail -f nohup.out
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        restart
        ;;
    status)
        status
        ;;
    logs)
        logs
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac
