import { createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { describe, expect, it, vi } from 'vitest';
import { I18nProvider, translateElement, translateText } from './i18n';

describe('i18n text translation', () => {
  it('keeps Chinese text in Chinese mode', () => {
    expect(translateText('入站与客户端', 'zh')).toBe('入站与客户端');
  });

  it('translates major page copy and dynamic messages in English mode', () => {
    const samples = [
      ['入站与客户端', 'Inbounds and clients'],
      ['导入代理池', 'Import proxy pool'],
      ['路由规则已保存', 'Routing rule saved'],
      ['应用 Xray 配置？', 'Apply Xray config?'],
      ['设置已保存，端口、数据库或基础路径变更需要重启服务后生效', 'Settings saved. Port, database, or base path changes require a service restart.'],
      ['Web 基础路径', 'Web base path'],
      ['TLS 证书文件', 'TLS cert file'],
      ['HY2 混淆密码', 'HY2 obfs password'],
      ['按来源入站、域名、IP、规则集或协议选择出站链路。', 'Choose outbound links by inbound source, domain, IP, rule set, or protocol.'],
      ['支持 geoip:cn、CIDR、单 IP，逗号或换行分隔。', 'Supports geoip:cn, CIDR, or single IP values separated by commas or newlines.'],
      ['登录失败，请检查用户名或密码', 'Login failed. Check username or password.'],
      ['节点已保存，但核心配置未生效', 'Node saved, but core config did not take effect'],
      ['配置已应用，但端口未监听：443/tcp', 'Config applied, but ports are not listening: 443/tcp'],
      ['应用到选中的 3 个入站', 'Apply to 3 selected inbounds'],
      ['将把当前证书应用到选中的 2 个入站，并重新应用对应核心配置。', 'Apply the current certificate to 2 selected inbounds and reapply the related core config.'],
      ['订阅顺序已保存，但核心配置未生效', 'Subscription order saved, but core config did not take effect'],
      ['暂不支持分享链接', 'Share links are not supported yet'],
      ['点击“加载日志”查看最近更新日志。', 'Click "Load logs" to view recent update logs.'],
      ['当前不可用', 'Currently unavailable'],
      ['当前可用', 'Currently available'],
      ['服务状态异常', 'Service status abnormal'],
      ['核心配置缺失', 'Core config missing'],
      ['正在下载并校验升级包', 'Downloading and verifying the update package'],
      ['升级包校验完成，正在替换二进制和服务文件', 'Update package verified. Replacing binary and service files'],
      ['上次更新状态长时间未完成，已标记为失败；可重新发起更新', 'The previous update did not finish for a long time and was marked failed. You can start another update.'],
      ['回滚失败，需要人工处理', 'Rollback failed; manual intervention required'],
      ['启动于', 'Started at'],
      ['certificate applied', 'Certificate applied'],
      ['renew failed', 'Renew failed'],
    ] as const;

    for (const [source, expected] of samples) {
      expect(translateText(source, 'en')).toBe(expected);
    }
  });

  it('keeps separate original text for multiple text nodes under one parent', () => {
    const host = document.createElement('div');
    host.append('入站');
    host.append(document.createElement('span'));
    host.append('出站');

    translateElement(host, 'en');
    expect(host.textContent).toBe('InboundsOutbounds');

    translateElement(host, 'zh');
    expect(host.textContent).toBe('入站出站');
  });

  it('does not restore stale Chinese over React-rendered English on language switches', () => {
    const host = document.createElement('div');
    host.append('1 活跃 · 0 过期 · 0 受限');

    translateElement(host, 'en');
    expect(host.textContent).toBe('1 Active · 0 Expiry · 0 Limited');

    host.textContent = '1 Active · 0 Expiry · 0 Limited';
    translateElement(host, 'en');
    expect(host.textContent).toBe('1 Active · 0 Expiry · 0 Limited');
  });

  it('skips diagnostic subtrees marked as no-i18n', () => {
    const host = document.createElement('div');
    host.append('服务状态');
    const diagnostic = document.createElement('pre');
    diagnostic.dataset.noI18n = 'true';
    diagnostic.title = '错误详情';
    diagnostic.textContent = '错误: /etc/migate/cert.pem 证书不可用';
    host.append(diagnostic);

    translateElement(host, 'en');
    expect(host.firstChild?.textContent).toBe('Service status');
    expect(diagnostic.textContent).toBe('错误: /etc/migate/cert.pem 证书不可用');
    expect(diagnostic.title).toBe('错误详情');
  });

  it('does not install a DOM mutation observer for implicit page translation', () => {
    const original = globalThis.MutationObserver;
    const observer = vi.fn();
    globalThis.MutationObserver = observer as never;
    const host = document.createElement('div');
    const root = createRoot(host);
    try {
      root.render(createElement(I18nProvider, null, createElement('div', null, '概览')));
      expect(observer).not.toHaveBeenCalled();
    } finally {
      root.unmount();
      globalThis.MutationObserver = original;
    }
  });
});
