import sys
import smtplib

if __name__ == '__main__':
    def prompt(prompt):
        sys.stdout.write(prompt + ': ')
        sys.stdout.flush()
        return sys.stdin.readline().strip()


    fromaddr = prompt('From')
    toaddrs = prompt('To').split(',')
    print('Enter message, end with ^D:')
    msg = ''
    while 1:
        line = sys.stdin.readline()
        if not line:
            break
        msg = msg + line
    print('Message length is %d' % len(msg))

    server = smtplib.SMTP('smtp.163.com')
    server.set_debuglevel(1)
    server.login('w1637894214@163.com', 'wjq4214')
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()
