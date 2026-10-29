export type AccountEmailPurpose = 'email_verification' | 'password_recovery';

export interface AccountActionEmail {
  purpose: AccountEmailPurpose;
  recipient: string;
  token: string;
  expiresAt: Date;
  language: 'en' | 'es';
}

export interface EmailProvider {
  sendAccountActionEmail(message: AccountActionEmail): Promise<void>;
}

/** Default adapter: records suppression metadata and deliberately discards the token. */
export class DisabledEmailProvider implements EmailProvider {
  async sendAccountActionEmail(message: AccountActionEmail): Promise<void> {
    void message.recipient;
    void message.token;
    void message.expiresAt;
    void message.language;
    process.stdout.write(`email.delivery.disabled purpose=${message.purpose}\n`);
  }
}

/** Test-only adapter that captures a simulated delivery for integration assertions. */
export class TestEmailProvider implements EmailProvider {
  readonly messages: AccountActionEmail[] = [];

  async sendAccountActionEmail(message: AccountActionEmail): Promise<void> {
    this.messages.push({ ...message });
  }

  takeLast(purpose?: AccountEmailPurpose): AccountActionEmail | undefined {
    const index = purpose
      ? this.messages.findLastIndex((message) => message.purpose === purpose)
      : this.messages.length - 1;
    if (index < 0) return undefined;
    const [message] = this.messages.splice(index, 1);
    return message;
  }
}
