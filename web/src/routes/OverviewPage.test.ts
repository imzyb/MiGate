import { describe, expect, it } from 'vitest';
import { engineStatusSummary, trafficStatusLabel, validationStatusLabel, validationSummary } from './OverviewPage';

const text = (value: string) => value;

describe('OverviewPage traffic status labels', () => {
  it('shows sing-box unsupported as an informational realtime stats limitation', () => {
    expect(trafficStatusLabel('unsupported', text)).toBe('当前 sing-box 二进制不支持实时统计');
    expect(engineStatusSummary({ xray: 'ok', singbox: 'unsupported' }, text)).toBe('xray: 统计正常 · singbox: 当前 sing-box 二进制不支持实时统计');
  });

  it('shows not_configured without treating it as a core failure label', () => {
    expect(trafficStatusLabel('not_configured', text)).toBe('未配置对应核心入站');
    expect(engineStatusSummary({ singbox: 'not_configured' }, text)).toBe('singbox: 未配置对应核心入站');
  });

  it('distinguishes waiting and unavailable labels', () => {
    expect(trafficStatusLabel('waiting', text)).toBe('等待采样');
    expect(trafficStatusLabel('unavailable', text)).toBe('统计接口不可用');
  });
});

describe('OverviewPage validation labels', () => {
  const enText = (value: string) => ({
    生成中: 'Generating',
    不可用: 'Unavailable',
    失败: 'Failed',
    通过: 'Passed',
    未知: 'Unknown',
    等待校验结果: 'Waiting for validation result',
  })[value] || value;

  it('uses explicit translations for validation status labels', () => {
    expect(validationStatusLabel({ loading: true }, enText)).toBe('Generating');
    expect(validationStatusLabel({ loading: false, error: new Error('boom') }, enText)).toBe('Unavailable');
    expect(validationStatusLabel({ loading: false, valid: false }, enText)).toBe('Failed');
    expect(validationStatusLabel({ loading: false, valid: true }, enText)).toBe('Passed');
    expect(validationStatusLabel({ loading: false }, enText)).toBe('Unknown');
  });

  it('uses explicit translations for empty validation summary', () => {
    expect(validationSummary(undefined, enText)).toBe('Waiting for validation result');
  });
});
