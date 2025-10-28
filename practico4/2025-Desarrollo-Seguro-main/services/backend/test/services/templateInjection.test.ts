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
      first_name: '<%= "INJECTED" %>',
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

    // En código vulnerable, el template se ejecuta y muestra "INJECTED"
    // En código seguro, debería estar escapado como "&lt;%= "INJECTED" %&gt;"
    expect(capturedEmailHtml).not.toContain('INJECTED');
    expect(capturedEmailHtml).toContain('&lt;%=');
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
      first_name: '<%= "test" + "injection" %>',
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

    // En código vulnerable ejecuta la concatenación y muestra "testinjection"
    // En código seguro debería escapar el template
    expect(capturedEmailHtml).not.toContain('testinjection');
    expect(capturedEmailHtml).toContain('&lt;%=');
  });

  it('prevent fs access', async () => {
    const user = {
      id: 'fs-test',
      email: 'fstest@example.com',
      password: 'test123',
      first_name: 'Normal',
      last_name: '<%= 2 + 2 %>',
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

    // En código vulnerable ejecuta 2+2 y muestra "4"
    // En código seguro debería estar escapado
    expect(capturedEmailHtml).not.toContain('Normal 4');
    expect(capturedEmailHtml).toContain('&lt;%=');
  });

  it('sanitize eval attempts', async () => {
    const user = {
      id: 'eval-test',
      email: 'evaltest@test.com',
      password: 'pwd',
      first_name: '<%= 1 + 1 %>',
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

    // En código vulnerable ejecuta 1+1 y muestra "2"
    // En código seguro debería estar escapado
    expect(capturedEmailHtml).not.toMatch(/^2\s/);
    expect(capturedEmailHtml).toContain('&lt;%=');
  });

  it('multiple attacks combined', async () => {
    const user = {
      id: 'ataque',
      email: 'Peluche@test.com',
      password: 'password',
      first_name: '<%= "attack" %><script>alert(1)</script>',
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

    // En código vulnerable: ejecuta template y no escapa HTML
    // En código seguro: debería escapar todo
    expect(capturedEmailHtml).not.toContain('attack<script>');
    expect(capturedEmailHtml).toContain('&lt;');
  });

  it('normal user data works', async () => {
    const normalUser = {
      id: 'normal-user',
      email: 'normal@test.com',
      password: 'normalpass',
      first_name: '<%= "template" %>',
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

    // En código vulnerable ejecuta el template
    // En código seguro debería rechazar o escapar
    expect(capturedEmailHtml).not.toContain('template Doe');
    expect(capturedEmailHtml).toContain('&lt;%=');
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
      first_name: '<%= "polluted" %>',
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

    // En código vulnerable ejecuta el template y muestra "polluted"
    // En código seguro debería estar escapado
    expect(capturedEmailHtml).not.toContain('polluted User');
    expect(capturedEmailHtml).toContain('&lt;%=');
  });
});
