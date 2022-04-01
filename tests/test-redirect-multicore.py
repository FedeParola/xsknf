#!/usr/bin/python3

import subprocess
import time

TESTER                = 'cube1@130.192.225.61'
IFNAME                = 'ens1f0'
MOONGEN_PATH          = '~/Federico/MoonGen/build/MoonGen'
APP_NAME              = 'load_balancer'
APP_PATH              = f'/home/polycube/src/af_xdp-tests/examples/{APP_NAME}/{APP_NAME}'
SERVICES_GEN_PATH     = f'/home/polycube/src/af_xdp-tests/examples/{APP_NAME}/gen-services.py'
PKTGEN_SCRIPT_PATH    = '/home/cube1/Federico/MoonGen/examples/test-rss.lua'
RX_QUEUES_SCRIPT_PATH = '/home/polycube/scripts/set-rx-queues-rss.sh'
RES_FILENAME          = 'res-redirect-multicore.csv'
RUNS                  = 5
RETRIES               = 10
TRIAL_TIME            = 30  # Seconds of a single test trial
FINAL_TRIAL_TIME      = 30
TESTS_GAP             = 5   # Seconds of gap between two tests
SESSIONS_COUNTS       = [1000, 100000, 1000000]
CORES_POOL            = [2, 4, 6, 8, 10, 12, 14]
MODES                 = ['af_xdp-bp']
FLAGS                 = {
                         'xdp': ['-M', 'XDP'],
                         'af_xdp': [],
                         'af_xdp-bp': ['-B'],
                         'af_xdp-poll': ['-p'],
                         'combined': ['-M', 'COMBINED'],
                         'combined-bp': ['-M', 'COMBINED', '-B'],
                         'combined-poll': ['-M', 'COMBINED', '-p']
                        }
MAX_TARGET            = 20000
TARGET_STEP           = 50
MAX_LOSS              = 0.001
PERF_COUNTERS         = ['LLC-loads', 'LLC-load-misses', 'LLC-stores',
                         'LLC-store-misses']
PERF_TIME             = 10  # Seconds

def round_target(target):
    return int(target / TARGET_STEP) * TARGET_STEP

def get_pktgen_stats():
    cmd = ['scp', f'{TESTER}:./tmp.csv' , '.']
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
    f = open("tmp.csv", "r")
    ret = f.read().splitlines()[1].split(';')
    f.close()
    return ret[2], int(ret[1]), int(ret[3])

out = open(RES_FILENAME, 'w')
out.write("run;sessions;cores;mode;throughput;target;llc-loads;llc-load-misses;llc-store;llc-store-misses;user;system;softirq;verified\n")

cmd = [SERVICES_GEN_PATH, '1', '10']
subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)

for run in range(RUNS):
    for sessions in SESSIONS_COUNTS:
        for cores in CORES_POOL:
            cmd = [RX_QUEUES_SCRIPT_PATH, str(cores), IFNAME]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

            for mode in MODES:
                print(f'Run {run}: measuring {sessions} sessions in mode {mode} on {cores} cores...')

                if mode == 'af_xdp-bp' or mode == 'combined-bp':
                    # Enable busy polling
                    cmd = ['sudo', 'tee',
                            f'/sys/class/net/{IFNAME}/napi_defer_hard_irqs']
                    subprocess.run(cmd, check=True, text=True, input='2',
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
                    cmd = ['sudo', 'tee',
                            f'/sys/class/net/{IFNAME}/gro_flush_timeout']
                    subprocess.run(cmd, check=True,  text=True, input='200000', 
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)

                cmd = ['taskset', format(2 ** cores - 1, 'x'), 'sudo', APP_PATH,
                        '-i', IFNAME, '-w', str(cores)] + FLAGS[mode] + ['--',
                        '-q', '-p', str(sessions)]
                app = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL)

                max_t = MAX_TARGET

                for retry in range(RETRIES):
                    print(f'Trial {retry}')

                    min_t = 0
                    curr_t = max_t
                    best_t = 0
                    best_r = 0

                    while max_t - min_t > TARGET_STEP:
                        print(f'Target {curr_t} Mbps')

                        cmd = ['ssh', TESTER, 'sudo', MOONGEN_PATH,
                                PKTGEN_SCRIPT_PATH, '0', '0', '-c', '6', '-o',
                                'tmp.csv', '-r', str(curr_t), '-t',
                                str(TRIAL_TIME), '-n', str(sessions)]
                        subprocess.run(cmd, check=True,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)      

                        rate, tx_pkts, rx_pkts = get_pktgen_stats()
                        loss = (tx_pkts - rx_pkts) / tx_pkts
                        print(f'Sent {tx_pkts}, received {rx_pkts}, rate {rate} Mpps, loss {(loss*100):.2f}%')

                        if loss <= MAX_LOSS:
                            best_t = curr_t
                            best_r = rate
                            min_t = curr_t
                        else:
                            max_t = curr_t

                        curr_t = round_target((max_t + min_t) / 2)

                    # Perform the cache run
                    print('Checking result, cache and CPU...')

                    cmd = ['ssh', TESTER, 'sudo', MOONGEN_PATH,
                            PKTGEN_SCRIPT_PATH, '0', '0', '-c', '6', '-o',
                            'tmp.csv', '-r', str(best_t), '-t',
                            str(FINAL_TRIAL_TIME), '-n', str(sessions)]
                    pktgen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)

                    time.sleep(5)

                    # Collect cache statistics
                    cmd = ['sudo', 'perf', 'stat', '-C', f'0-{cores - 1}',
                            '--no-big-num', '-e', ','.join(PERF_COUNTERS), 
                            'sleep', str(PERF_TIME)]
                    res = subprocess.run(cmd, check=True, capture_output=True,
                            text=True).stderr
                    reslines = res.splitlines()
                    loads        = int(int(reslines[3].split()[0]) / PERF_TIME)
                    load_misses  = int(int(reslines[4].split()[0]) / PERF_TIME)
                    stores       = int(int(reslines[5].split()[0]) / PERF_TIME)
                    store_misses = int(int(reslines[6].split()[0]) / PERF_TIME)

                    # Collect CPU statistics
                    cmd = ['sar', '-P', f'0-{cores - 1}', '-u', 'ALL', '10',
                            '1']
                    res = subprocess.run(cmd, check=True, capture_output=True,
                            text=True).stdout.splitlines()
                    user = 0
                    system = 0
                    softirq = 0
                    for i in range(cores):
                        user    += float(res[3 + i].split()[3])
                        system  += float(res[3 + i].split()[5])
                        softirq += float(res[3 + i].split()[9])

                    pktgen.wait()

                    rate, tx_pkts, rx_pkts = get_pktgen_stats()
                    loss = (tx_pkts - rx_pkts) / tx_pkts
                    if loss <= MAX_LOSS:
                        verified = True
                    else:
                        verified = False

                    print(f'Target {best_t} Mbps, throughput: {best_r} Mpps, {"VERIFIED" if verified else f"NOT VERIFIED (lost {loss*100:.2f}%)"}, User {user:.2f}%, System {system:.2f}%, SoftIRQ {softirq:.2f}%\n')

                    if verified:
                        break
                    else:
                        max_t = best_t - TARGET_STEP
                        time.sleep(TESTS_GAP)

                cmd = ['sudo', 'killall', APP_NAME]
                subprocess.run(cmd, check=True)

                out.write(f'{run};{sessions};{cores};{mode};{best_r};{best_t};{loads};{load_misses};{stores};{store_misses};{user:.2f};{system:.2f};{softirq:.2f};{verified}\n')
                out.flush()

                if mode == 'af_xdp-bp' or mode == 'combined-bp':
                    # Disable busy polling
                    cmd = ['sudo', 'tee',
                            f'/sys/class/net/{IFNAME}/napi_defer_hard_irqs']
                    subprocess.run(cmd, check=True, text=True, input='0',
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    cmd = ['sudo', 'tee',
                            f'/sys/class/net/{IFNAME}/gro_flush_timeout']
                    subprocess.run(cmd, check=True,  text=True, input='0', 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                time.sleep(TESTS_GAP)

out.close()