import { logger } from './logger'
import { validateInviteCode } from './validateInviteCode.js'

jest.mock('./logger.js', () => ({
  logger: {
    error: jest.fn()
  }
}))

describe('validateInviteCode', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should validate a valid invite code with hyphens and a single slash', () => {
    const inviteCode =
      '196029f9-777b-428a-8f20-61130482b12d/yry4pdqoh6rp8qpi7rizmrrbik3f6789cxaj6o5xakauxadiy1dnd88dzmjzer576zrxomm78a7br665jsfdq1j3361th99d6retsobnra'

    expect(validateInviteCode(inviteCode)).toBe(inviteCode)
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('should validate legacy invite code (backward compatible)', () => {
    const legacyCode =
      'mk2a7bnvuujzyw706qh/yry9qnyupy4eauuubxfsh1bd8hf3suftz4wbszu3gafm51ym7aax4rmsm5t771w9g8d55rekyrp95k3458gtmegrybmdip9g9n3p5snp8e'
    expect(validateInviteCode(legacyCode)).toBe(legacyCode)
    expect(logger.error).not.toHaveBeenCalled()
  })

  it('should throw an error for code with multiple slashes', () => {
    const codeWithSlash = 'a'.repeat(50) + '/b'.repeat(51)

    expect(() => validateInviteCode(codeWithSlash)).toThrow(
      'Invalid invite code'
    )
    expect(logger.error).toHaveBeenCalled()
  })

  it('should throw an error for code without a slash', () => {
    const codeWithoutSlash = 'a'.repeat(120)

    expect(() => validateInviteCode(codeWithoutSlash)).toThrow(
      'Invalid invite code'
    )
    expect(logger.error).toHaveBeenCalled()
  })

  it('should throw an error for code that is too short', () => {
    const shortCode = 'a'.repeat(99)

    expect(() => validateInviteCode(shortCode)).toThrow('Invalid invite code')
    expect(logger.error).toHaveBeenCalled()
  })

  it('should throw an error for code with invalid characters', () => {
    const invalidCode = 'a'.repeat(50) + '!@#$%^&*()' + 'a'.repeat(50)

    expect(() => validateInviteCode(invalidCode)).toThrow('Invalid invite code')
    expect(logger.error).toHaveBeenCalled()
  })

  it('should throw an error for code with invalid format', () => {
    const invalidFormat = 'a'.repeat(50) + '/b'.repeat(30) + '/c'.repeat(30)

    expect(() => validateInviteCode(invalidFormat)).toThrow(
      'Invalid invite code'
    )
    expect(logger.error).toHaveBeenCalled()
  })

  it('should throw an error for non-string input', () => {
    expect(() => validateInviteCode(null)).toThrow()
    expect(() => validateInviteCode(undefined)).toThrow()
    expect(() => validateInviteCode(123)).toThrow()
    expect(logger.error).toHaveBeenCalled()
  })
})
