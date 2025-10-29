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
      id: 'sapo-123',
      email: 'sapo@test.com',
      password: 'pass123',
      first_name: '<%= process.exit(1) %>',
      last_name: 'Usuario',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });

  it('escape script tags', async () => {
    const user = {
      id: 'test1899',
      email: 'xd@example.com',
      password: 'password',
      first_name: '<script>alert("XSS")</script>',
      last_name: 'Normal',
      username: 'xduser',
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
  });

  it('prevent require injection', async () => {
    const user = {
      id: 'requerido-user',
      email: 'requerido@test.com',
      password: 'requerido1899',
      first_name: '<% const fs = require("fs"); %>',
      last_name: 'Tester',
      username: 'requerido',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });

  it('prevent fs access', async () => {
    const user = {
      id: 'fs-test',
      email: 'fs@mail.com',
      password: 'fspass',
      first_name: 'Regular',
      last_name: '<%= require("fs").readFileSync("package.json") %>',
      username: 'fsuser',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });

  it('sanitize eval attempts', async () => {
    const user = {
      id: '100pies-test',
      email: '100pies@example.org',
      password: 'cienpies',
      first_name: '<% eval("malicious code") %>',
      last_name: 'PepeSape',
      username: 'pepeuser',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });

  it('multiple attacks combined', async () => {
    const user = {
      id: 'multi-attack',
      email: 'multi@hacker.net',
      password: 'multipass',
      first_name: '<%= 1+1 %>',
      last_name: '<script>bad()</script>',
      username: 'multiuser',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });

  it('normal user data works', async () => {
    const user = {
      id: 'normal-user',
      email: 'normal@email.com',
      password: 'normalpass',
      first_name: 'Alice',
      last_name: 'Johnson',
      username: 'alice123',
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

    expect(capturedEmailHtml).toContain('Alice');
    expect(capturedEmailHtml).toContain('Johnson');
  });

  it('handle special characters', async () => {
    const user = {
      id: 'special-chars',
      email: 'special@test.com',
      password: 'specialpass',
      first_name: "O'Brien",
      last_name: 'López-García',
      username: 'special_user',
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

    expect(capturedEmailHtml).toMatch(/O&#39;Brien|O'Brien/);
    expect(capturedEmailHtml).toContain('López-García');
  });

  it('prevent prototype pollution', async () => {
    const user = {
      id: 'abitab-test',
      email: 'abiitab@test.com',
      password: 'abitab',
      first_name: '<% constructor.prototype.polluted = "hacked" %>',
      last_name: 'abitab',
      username: 'abitabuser',
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

    await expect(AuthService.createUser(user)).rejects.toThrow('Invalid input: template tokens are not allowed in text fields');
  });
});
