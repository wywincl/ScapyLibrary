#!/usr/bin/env python
# -*- coding: utf8 -*-
from keywords import *
from version import VERSION

__version__ = VERSION


class Scapy2Library(_LoggingKeywords, _RunOnFailureKeywords, _ScapyKeywords):
    """
    Scapy2Library 是一个Robot Framework下的发包收包测试库.
    它使用了Scapy库作为基础，所以必须运行在安装有Scapy库的环境中.

    Author: John.Wang <wywincl@gmail.com>
    = Example =

    |  *Setting*  |     *Value*     |
    | Library     |  Scapy2Library  |

    | *Variable*  |       *Value*         |
    | ${SRC_MAC}  |  00:00:00:00:00:01    |
    | ${SRC_IP}   |     192.168.0.233     |
    | ${VLAN_ID}  |       ${1111}         |

    | *Test Case* |     *Action*      |  *Argument*  |    *Argument*   |    *Argument*   |
    | Example     | Send Igmp Query   |  ${SRC_MAC}  |    ${VLAN_ID}   |    ${SRC_IP}    |
    """
    ROBOT_LIBRARY_SCOPE = "GLOBAL"
    ROBOT_LIBRARY_VERSION = __version__

    def __init__(self, run_on_failure='Nothing'):
        """Scapy2Library 库可以带参数启动.

        当Scapy2Library 关键字运行失败时，`run_on_failure` 执行具体的关键字(从可获得的库中导入)来处理失败情况 .
        如果使用关键字Nothing 作为参数，当Scapy2Library 关键字执行失败时，则不执行任何操作. 查看
        `Register Keyword To Run On Failure` 关键字去获取更多信息。

        Examples:
        | Library | Scapy2Library |
        | Library | Scapy2Library | run_on_failure=Log Source | # runs `Log Source` on failure |
        | Library | Scapy2Library | run_on_failure=Nothing    | # does nothing on failure      |
        """
        for base in Scapy2Library.__bases__:
            base.__init__(self)
        self.register_keyword_to_run_on_failure(run_on_failure)
