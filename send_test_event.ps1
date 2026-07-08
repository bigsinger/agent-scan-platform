# Agent Security Assessment v4.2 — 探针事件上报测试
# 用法: 在启动服务后运行此脚本

$BaseUrl = "http://127.0.0.1:8000"

Write-Host "╔════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   Agent Security 探针事件上报测试            ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. 健康检查
Write-Host "[1/5] 健康检查..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/api/v1/observability/health" -TimeoutSec 3
    Write-Host "  ✓ 可观测性健康: $($health.receiver.status)" -ForegroundColor Green
    Write-Host "  ✓ 数据库事件数: $($health.database.total_probe_events)"
} catch {
    Write-Host "  ✗ 服务未就绪: $_" -ForegroundColor Red
    exit 1
}

# 2. 上报一条普通事件
Write-Host "[2/5] 上报普通探针事件..." -ForegroundColor Yellow
$body = @{
  events = @(
    @{
      event_id = "evt-demo-$(Get-Random -Maximum 99999)"
      event_type = "tool.call.started"
      timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
      source_agent = "codex"
      session_id = "demo-session"
      trace_id = "abcdef1234567890abcdef1234567890"
      span_id = "1111222233334444"
      tool_call_id = "call-demo"
      tool_name = "Bash"
      tool_type = "shell"
      phase = "start"
      status = "ok"
      redaction_status = "redacted"
      payload = @{ command = "echo hello world" }
    }
  )
} | ConvertTo-Json -Depth 10

try {
    $result = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/probes/events" -ContentType "application/json" -Body $body
    Write-Host "  ✓ accepted=$($result.accepted) rejected=$($result.rejected)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ 上报失败: $_" -ForegroundColor Red
}

# 3. 上报一条含敏感信息的事件（验证脱敏）
Write-Host "[3/5] 上报含 secret 的事件（验证脱敏）..." -ForegroundColor Yellow
$secretBody = @{
  events = @(
    @{
      event_id = "evt-sec-$(Get-Random -Maximum 99999)"
      event_type = "tool.call.completed"
      timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
      source_agent = "codex"
      session_id = "demo-session"
      tool_name = "Bash"
      tool_type = "shell"
      phase = "complete"
      status = "ok"
      redaction_status = "redacted"
      payload = @{
        command = "curl -H 'Authorization: Bearer sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' https://api.example.com"
        password = "my-secret-123"
      }
    }
  )
} | ConvertTo-Json -Depth 10

try {
    $result2 = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/probes/events" -ContentType "application/json" -Body $secretBody
    Write-Host "  ✓ accepted=$($result2.accepted) rejected=$($result2.rejected)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ 上报失败: $_" -ForegroundColor Red
}

# 4. 查询事件
Write-Host "[4/5] 查询已上报事件..." -ForegroundColor Yellow
try {
    $events = Invoke-RestMethod -Uri "$BaseUrl/api/v1/probes/events?limit=5" -TimeoutSec 3
    Write-Host "  ✓ 共 $($events.total) 条事件，返回 $($events.items.count) 条" -ForegroundColor Green
    
    # 验证脱敏
    foreach ($ev in $events.items) {
        $p = $ev.payload
        if ($p.command -match "Bearer") {
            if ($p.command -match "\[REDACTED\]") {
                Write-Host "  ✓ 脱敏验证通过: $($ev.event_id)" -ForegroundColor Green
            } else {
                Write-Host "  ✗ 脱敏验证失败: secret 未脱敏!" -ForegroundColor Red
            }
        }
        if ($p.password) {
            if ($p.password -eq "[REDACTED]") {
                Write-Host "  ✓ 脱敏验证通过: password 字段" -ForegroundColor Green
            } else {
                Write-Host "  ✗ 脱敏验证失败: password 未脱敏!" -ForegroundColor Red
            }
        }
    }
} catch {
    Write-Host "  ✗ 查询失败: $_" -ForegroundColor Red
}

# 5. 查看会话和异常规则
Write-Host "[5/5] 查看会话和规则..." -ForegroundColor Yellow
try {
    $sessions = Invoke-RestMethod -Uri "$BaseUrl/api/v1/probe-sessions" -TimeoutSec 3
    Write-Host "  ✓ 共 $($sessions.total) 个会话" -ForegroundColor Green
    
    $rules = Invoke-RestMethod -Uri "$BaseUrl/api/v1/behavior/rules" -TimeoutSec 3
    Write-Host "  ✓ 共 $($rules.total) 条异常规则" -ForegroundColor Green
    foreach ($rule in $rules.items) {
        Write-Host "    $($rule.rule_id): $($rule.title) [$($rule.severity)]"
    }
} catch {
    Write-Host "  ✗ 查询失败: $_" -ForegroundColor Red
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "测试完成" -ForegroundColor Cyan
Write-Host "═════════════════════════════════════════════════════" -ForegroundColor Cyan
pause
