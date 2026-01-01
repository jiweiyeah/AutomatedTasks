-- 域名检测进度表（用于断点续作）
-- 记录每个域名在每次任务中的检测状态，支持中断后恢复

CREATE TABLE IF NOT EXISTS domain_check_progress (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- 任务标识
    task_date DATE NOT NULL,                    -- 任务日期
    tier VARCHAR(20) NOT NULL,                  -- 订阅等级: free, pro, premium
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    
    -- 检测状态
    status VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending, checking, completed, failed
    ssl_status VARCHAR(20),                         -- valid, expiring, expired, error
    checked_at TIMESTAMP WITH TIME ZONE,            -- 检测完成时间
    error_message TEXT,                             -- 错误信息（失败时）
    
    -- 通知状态（用于去重）
    notification_sent BOOLEAN DEFAULT FALSE,        -- 是否已发送通知
    
    -- 时间戳
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- 唯一约束：每个域名每天每个等级只有一条记录
    CONSTRAINT unique_domain_check_progress UNIQUE(task_date, tier, domain_id)
);

-- 索引优化查询性能
-- 按任务日期和等级查询（最常用）
CREATE INDEX IF NOT EXISTS idx_domain_check_progress_task 
    ON domain_check_progress(task_date, tier);

-- 按状态过滤（用于获取待处理/已完成的域名）
CREATE INDEX IF NOT EXISTS idx_domain_check_progress_status 
    ON domain_check_progress(task_date, tier, status);

-- 按域名查询（用于检查单个域名的进度）
CREATE INDEX IF NOT EXISTS idx_domain_check_progress_domain 
    ON domain_check_progress(domain_id, task_date);

-- 添加注释
COMMENT ON TABLE domain_check_progress IS '域名检测进度表，用于实现断点续作机制';
COMMENT ON COLUMN domain_check_progress.status IS '检测状态: pending-待检测, checking-检测中, completed-已完成, failed-失败';
COMMENT ON COLUMN domain_check_progress.ssl_status IS 'SSL证书状态: valid-有效, expiring-即将过期, expired-已过期, error-检测错误';
COMMENT ON COLUMN domain_check_progress.notification_sent IS '是否已发送通知，用于防止重复发送';
