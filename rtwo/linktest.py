"""
Instance Link Testing.
"""
import multiprocessing

import requests

from threepio import logger


class LinkTestProcess(multiprocessing.Process):
    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        #proc_name = self.name
        while True:
            #Do work
            next_task = self.task_queue.get()
            if next_task is None:
                break
            result = next_task()
            self.result_queue.put(result)
        return


class LinkTestTask():
    def __init__(self, alias, uri):
        self.alias = alias
        self.uri = uri

    def __call__(self):
        link_results = test_instance_links(self.alias, self.uri)
        return link_results

    def __str__(self):
        return "%s" % (self.instance)


def test_instance_links(alias, uri):
    #logger.debug(uri)
    shell_address = 'http://%s:4200' % uri
    shell_success = test_link(shell_address)
    vnc_address = 'http://%s:5904' % uri
    vnc_success = test_link(vnc_address)
    return {alias: {'vnc': vnc_success, 'shell': shell_success}}


def test_link(address):
    if not address:
        return False
    try:
        response = requests.head(address, timeout=9.0)
        if response.status_code in [200, 302]:
            return True
        return False
    except requests.ConnectionError, error:
        err_code, err_reason = error.args[0].reason
        logger.warn("Link test failed: URL:%s Error:%s - %s" % (address, err_code, err_reason))
        return False
    except Exception as e:
        logger.exception(e)
        return False

def active_instances(instances):
    return active_instances_naive(instances)

def active_instances_naive(instances):
    test_results = {}
    for instance in instances:
        if instance.ip is not None and instance.extra['status'] == 'active':
            link_results = test_instance_links(instance.alias, instance.ip)
        else:
            logger.info("Not testing %s:%s-%s" % (instance,
                                               instance.ip,
                                               instance.extra['status']))
        test_results.update(link_results)
    return test_results

def active_instances_threaded(instances):
    """
    Creates multiple processes to test instance links
    """
    test_results = {}

    # Determine #processes and #jobs
    num_processes = multiprocessing.cpu_count() * 2
    num_jobs = len(instances)
    # logger.debug("Created %d processes to run %s jobs" %
    #             (num_processes, num_jobs))

    # Create input and output queue
    tasks = multiprocessing.Queue()
    results = multiprocessing.Queue()

    processes = [LinkTestProcess(tasks, results)
                 for i in xrange(num_processes)]
    for p in processes:
        p.start()
        # logger.info("Started %d processes" % (num_processes,))

    for i in instances:
        # Task to run on idle processes
        tasks.put(LinkTestTask(i.alias, i.ip))
        # logger.info("Added %d tasks" % (num_jobs,))

    for _ in xrange(num_processes):
        # Sentinal value to kill the proc
        tasks.put(None)
        # logger.info("Added %d poison pills" % (num_processes,))

    while num_jobs:
        # logger.info("in num_jobs")
        # logger.info(results)
        try:
            result = results.get()
            if result:
                test_results.update(result)
        except Exception:
            logger.exception("Problem with multiprocessing queue.")
        num_jobs -= 1

    #logger.info("Threads complete. Returning response")
    return test_results
