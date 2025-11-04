from flask import Flask, request, Response, stream_with_context, send_from_directory
from flask_cors import CORS
import socket
import json
import time
from datetime import datetime
import threading
from queue import Queue
import os

app = Flask(__name__)
CORS(app)

# 配置访问密钥
ACCESS_KEY = "131313"

def scan_port(ip, port, timeout=1):
    """扫描单个端口"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_service_name(port):
    """获取常见端口的服务名称"""
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Proxy",
        8888: "HTTP-Alt", 9090: "HTTP-Alt", 27017: "MongoDB"
    }
    return services.get(port, "Unknown")

def scan_ports_worker(ip, port_queue, result_queue, timeout, stop_event):
    """工作线程扫描端口"""
    while not port_queue.empty() and not stop_event.is_set():
        try:
            port = port_queue.get(timeout=0.1)
            is_open = scan_port(ip, port, timeout)
            if is_open:
                result = {
                    "port": port,
                    "status": "open",
                    "service": get_service_name(port)
                }
                result_queue.put(result)
            port_queue.task_done()
        except Exception as e:
            break

def generate_scan_events(ip, start_port, end_port, timeout, threads):
    """生成 SSE 事件流"""
    
    stop_event = threading.Event()
    
    try:
        # 发送开始事件
        yield f"data: {json.dumps({'type': 'start', 'ip': ip, 'start_port': start_port, 'end_port': end_port, 'timestamp': datetime.now().isoformat()})}\n\n"
        
        port_queue = Queue()
        result_queue = Queue()
        
        # 填充端口队列
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        
        # 创建工作线程
        workers = []
        for _ in range(threads):
            worker = threading.Thread(
                target=scan_ports_worker,
                args=(ip, port_queue, result_queue, timeout, stop_event)
            )
            worker.daemon = True
            worker.start()
            workers.append(worker)
        
        # 实时发送结果
        total_ports = end_port - start_port + 1
        scanned = 0
        open_ports = []
        last_progress_update = 0
        
        while scanned < total_ports:
            try:
                # 检查是否有开放的端口
                while not result_queue.empty():
                    result = result_queue.get(timeout=0.1)
                    open_ports.append(result)
                    yield f"data: {json.dumps({'type': 'port_open', **result})}\n\n"
                
                # 计算进度
                current_scanned = total_ports - port_queue.qsize()
                
                # 每扫描50个端口或每秒更新一次进度
                if current_scanned - last_progress_update >= 50 or scanned == 0:
                    scanned = current_scanned
                    progress = (scanned / total_ports) * 100
                    yield f"data: {json.dumps({'type': 'progress', 'scanned': scanned, 'total': total_ports, 'progress': round(progress, 2)})}\n\n"
                    last_progress_update = scanned
                else:
                    scanned = current_scanned
                
                time.sleep(0.2)
                
            except GeneratorExit:
                # 客户端断开连接
                stop_event.set()
                raise
            except Exception as e:
                pass
        
        # 等待所有线程完成（最多等待5秒）
        for worker in workers:
            worker.join(timeout=5)
        
        # 检查剩余结果
        while not result_queue.empty():
            try:
                result = result_queue.get(timeout=0.1)
                open_ports.append(result)
                yield f"data: {json.dumps({'type': 'port_open', **result})}\n\n"
            except:
                break
        
        # 发送完成事件
        yield f"data: {json.dumps({'type': 'complete', 'open_ports': open_ports, 'total_open': len(open_ports), 'timestamp': datetime.now().isoformat()})}\n\n"
        
    except GeneratorExit:
        # 客户端断开连接，清理资源
        stop_event.set()
    except Exception as e:
        # 发送错误事件
        try:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        except:
            pass
    finally:
        # 确保停止所有线程
        stop_event.set()

@app.route('/sse', methods=['GET'])
def sse_scan():
    """SSE 端口扫描端点"""
    
    # 验证密钥
    key = request.args.get('key', '')
    if key != ACCESS_KEY:
        return Response(
            f"data: {json.dumps({'type': 'error', 'message': 'Invalid access key'})}\n\n",
            mimetype='text/event-stream'
        )
    
    # 获取参数
    ip = request.args.get('ip', '127.0.0.1')
    
    try:
        start_port = int(request.args.get('start_port', '1'))
        end_port = int(request.args.get('end_port', '1000'))
        timeout = float(request.args.get('timeout', '0.5'))
        threads = int(request.args.get('threads', '20'))
    except ValueError:
        return Response(
            f"data: {json.dumps({'type': 'error', 'message': 'Invalid parameters'})}\n\n",
            mimetype='text/event-stream'
        )
    
    # 参数验证
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        return Response(
            f"data: {json.dumps({'type': 'error', 'message': 'Invalid port range (1-65535)'})}\n\n",
            mimetype='text/event-stream'
        )
    
    # 限制端口范围，避免扫描时间过长
    if end_port - start_port > 10000:
        return Response(
            f"data: {json.dumps({'type': 'error', 'message': 'Port range too large (max 10000)'})}\n\n",
            mimetype='text/event-stream'
        )
    
    if threads < 1 or threads > 100:
        threads = 20
    
    if timeout < 0.1 or timeout > 5:
        timeout = 0.5
    
    # 返回 SSE 流
    return Response(
        stream_with_context(generate_scan_events(ip, start_port, end_port, timeout, threads)),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

@app.route('/scan', methods=['POST'])
def api_scan():
    """REST API 端口扫描端点（返回完整结果）"""
    
    # 验证密钥
    data = request.get_json()
    if not data or data.get('key') != ACCESS_KEY:
        return {"error": "Invalid access key"}, 403
    
    ip = data.get('ip', '127.0.0.1')
    start_port = data.get('start_port', 1)
    end_port = data.get('end_port', 1000)
    timeout = data.get('timeout', 0.5)
    threads = data.get('threads', 20)
    
    # 参数验证
    if end_port - start_port > 10000:
        return {"error": "Port range too large (max 10000)"}, 400
    
    # 扫描端口
    port_queue = Queue()
    result_queue = Queue()
    stop_event = threading.Event()
    
    for port in range(start_port, end_port + 1):
        port_queue.put(port)
    
    workers = []
    for _ in range(threads):
        worker = threading.Thread(
            target=scan_ports_worker,
            args=(ip, port_queue, result_queue, timeout, stop_event)
        )
        worker.start()
        workers.append(worker)
    
    # 等待所有线程完成（最多等待60秒）
    for worker in workers:
        worker.join(timeout=60)
    
    # 收集结果
    open_ports = []
    while not result_queue.empty():
        try:
            open_ports.append(result_queue.get(timeout=0.1))
        except:
            break
    
    return {
        "ip": ip,
        "start_port": start_port,
        "end_port": end_port,
        "open_ports": open_ports,
        "total_open": len(open_ports),
        "timestamp": datetime.now().isoformat()
    }

@app.route('/health', methods=['GET'])
def health():
    """健康检查端点"""
    return {"status": "ok", "service": "Port Scanner MCP", "version": "1.0"}

# 只保留这一个 index 路由
@app.route('/', methods=['GET'])
def index():
    """返回 HTML 页面或 API 信息"""
    # 检查是否存在 scanner.html 文件
    if os.path.exists('scanner.html'):
        return send_from_directory('.', 'scanner.html')
    else:
        # 如果没有 HTML 文件，返回 API 信息
        return {
            "service": "Port Scanner MCP",
            "version": "1.0",
            "endpoints": {
                "/": "Web Interface (if scanner.html exists)",
                "/sse": "SSE stream endpoint (GET)",
                "/scan": "REST API endpoint (POST)",
                "/health": "Health check"
            },
            "example": {
                "sse": "/sse?key=131313&ip=127.0.0.1&start_port=1&end_port=1000&threads=20&timeout=0.5",
                "scan": "POST /scan with JSON body: {\"key\":\"131313\",\"ip\":\"127.0.0.1\",\"start_port\":1,\"end_port\":1000}"
            },
            "note": "Put scanner.html in the same directory to enable web interface"
        }

if __name__ == '__main__':
    # 使用 0.0.0.0 以允许外部访问
    print("=" * 60)
    print("🚀 Port Scanner MCP Server Started!")
    print("=" * 60)
    
    # 检查 HTML 文件
    if os.path.exists('scanner.html'):
        print("✅ Web Interface: ENABLED")
        print(f"🌐 Open: http://0.0.0.0:9090")
    else:
        print("⚠️  Web Interface: DISABLED (scanner.html not found)")
        print("💡 Put scanner.html in the same directory to enable web UI")
    
    print(f"📡 API Server: http://0.0.0.0:9090")
    print(f"🔑 Access Key: {ACCESS_KEY}")
    print("=" * 60)
    print("📋 API Endpoints:")
    print("   GET  /          - Web Interface or API Info")
    print("   GET  /sse       - SSE Scan Stream")
    print("   POST /scan      - REST API Scan")
    print("   GET  /health    - Health Check")
    print("=" * 60)
    
    app.run(host='0.0.0.0', port=9090, debug=False, threaded=True)
