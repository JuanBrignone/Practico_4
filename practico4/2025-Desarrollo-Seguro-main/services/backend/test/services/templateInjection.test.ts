import nodemailer from 'nodemailer';
import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>

jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

let capturedEmailHtml: string = '';

mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: jest.fn().mockImplementation((mailOptions) => {
    capturedEmailHtml = mailOptions.html;
    return Promise.resolve({ success: true });
  }),
});

describe('Template Injection Tests', () => {
  beforeEach (() => {
    jest.resetModules();
    jest.clearAllMocks();
    capturedEmailHtml = '';
  });

  it('prevent EJS injection first_name', async () => {
    const user = {
      id: 'test-123',
      email: 'test@test.com',
      password: 'pass123',
      first_name: '<%= process.exit(1) %>',
      last_name: 'User',
      username: 'testuser',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('process.exit');
    expect(capturedEmailHtml).toContain('&lt;%= process.exit(1) %&gt;');
  });

  it('sanitize EJS code in last_name', async () => {
    const user = {
      id: 'usr-456',
      email: 'attacker@mail.com',
      password: 'test',
      first_name: 'John',
      last_name: '<% if(global.process.mainModule.require) { %><% } %>',
      username: 'hacker1',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };

    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toMatch(/<%[\s\S]*%>/);
    expect(capturedEmailHtml).toContain('&lt;%');
  });

  it('escape script tags', async () => {
    const user = {
      id: 'test-789',
      email: 'xss@example.com',
      password: 'password',
      first_name: '<script>alert("XSS")</script>',
      last_name: 'Normal',
      username: 'xssuser',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('<script>');
    expect(capturedEmailHtml).toContain('&lt;script&gt;');
  });

  it('prevent require injection', async () => {
    const user = {
      id: 'test-abc',
      email: 'test2@example.com',
      password: 'pass',
      first_name: '<%= global.process.mainModule.require("child_process").execSync("whoami") %>',
      last_name: 'TestUser',
      username: 'injector',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('require');
    expect(capturedEmailHtml).not.toContain('execSync');
  });

  it('prevent fs access', async () => {
    const user = {
      id: 'fs-test',
      email: 'fstest@example.com',
      password: 'test123',
      first_name: 'Normal',
      last_name: '<%= require("fs").readFileSync("/etc/passwd", "utf8") %>',
      username: 'fsattacker',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('readFileSync');
    expect(capturedEmailHtml).not.toContain('/etc/passwd');
  });

  it('sanitize eval attempts', async () => {
    const user = {
      id: 'eval-test',
      email: 'evaltest@test.com',
      password: 'pwd',
      first_name: '<%= eval("console.log(process.env)") %>',
      last_name: 'User',
      username: 'evaluser',
    } as User;

    const chain1 = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const chain2 = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(chain1 as any)
      .mockReturnValueOnce(chain2 as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('eval(');
  });

  it('multiple attacks combined', async () => {
    const user = {
      id: 'ataque',
      email: 'Peluche@test.com',
      password: 'password',
      first_name: '<%= 1+1 %><script>alert(1)</script>',
      last_name: '<% } %><img src=x onerror=alert(1)>',
      username: 'atacante',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).not.toContain('<script>');
    expect(capturedEmailHtml).not.toMatch(/<%=.*%>/);
    expect(capturedEmailHtml).not.toContain('onerror=');
  });

  it('normal user data works', async () => {
    const normalUser = {
      id: 'normal-user',
      email: 'normal@test.com',
      password: 'normalpass',
      first_name: 'John',
      last_name: 'Doe',
      username: 'johndoe',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(normalUser);

    expect(capturedEmailHtml).toContain('John');
    expect(capturedEmailHtml).toContain('Doe');
    expect(capturedEmailHtml).toContain('here</a>');
  });

  it('handle special characters', async () => {
    const user = {
      id: 'special-chars',
      email: 'special@test.com',
      password: 'pass',
      first_name: "O'Connor",
      last_name: 'Smith & Co.',
      username: 'special123',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(user);

    expect(capturedEmailHtml).toContain("O&#39;Connor");
    expect(capturedEmailHtml).toContain('Smith &amp; Co.');
  });

  it('prevent prototype pollution', async () => {
    const malicious = {
      id: 'proto-test',
      email: 'proto@test.com',
      password: 'test',
      first_name: '<%= constructor.constructor("return process")().exit() %>',
      last_name: 'User',
      username: 'protouser',
    } as User;

    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null)
    };
    const insertChain = {
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

    await AuthService.createUser(malicious);

    expect(capturedEmailHtml).not.toContain('constructor');
    expect(capturedEmailHtml).not.toContain('process');
  });
});
