#!/usr/bin/env python
# -*- coding: utf8 -*-
from robot.libraries import BuiltIn
from keywordgroup import KeywordGroup

BUILTIN = BuiltIn.BuiltIn()


class _RunOnFailureKeywords(KeywordGroup):
    def __init__(self):
        self._run_on_failure_keyword = None
        self._running_on_failure_routine = False

    # Public

    def register_keyword_to_run_on_failure(self, keyword):
        """
        函数简介：注册关键字运行失败时的执行动作.

        `keyword_name` 是从可导入库中导入的关键字，当Scapy2Library关键字执行失败时，
        执行这个关键字。使用关键字Nothing 会是这个功能在整个过程中失效。即关键字
        运行失败也也不做操作。

        Example:
        | Register Keyword To Run On Failure  | Log Source | # Run `Log Source` on failure. |
        | ${previous kw}= | Register Keyword To Run On Failure  | Nothing |
        | Register Keyword To Run On Failure  | ${previous kw} | # Restore to the previous keyword. |

        run-on-failure 只在 Python/Jython 2.4 + 生效
        """
        old_keyword = self._run_on_failure_keyword
        old_keyword_text = old_keyword if old_keyword is not None else "No keyword"

        new_keyword = keyword if keyword.strip().lower() != "nothing" else None
        new_keyword_text = new_keyword if new_keyword is not None else "No keyword"

        self._run_on_failure_keyword = new_keyword
        self._info('%s will be run on failure.' % new_keyword_text)

        return old_keyword_text

    # Private

    def _run_on_failure(self):
        if self._run_on_failure_keyword is None:
            return
        if self._running_on_failure_routine:
            return
        self._running_on_failure_routine = True
        try:
            BUILTIN.run_keyword(self._run_on_failure_keyword)
        except Exception, err:
            self._run_on_failure_error(err)
        finally:
            self._running_on_failure_routine = False

    def _run_on_failure_error(self, err):
        err = "Keyword '%s' could not be run on failure: %s" % (self._run_on_failure_keyword, err)
        if hasattr(self, '_warn'):
            self._warn(err)
            return
        raise Exception(err)
