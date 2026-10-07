import logging

import azure.functions as func

from ast_sync import run_sync

# Keep the log to one summary line per run instead of one line per HTTP request.
for noisy in ("httpx", "httpcore", "azure", "azure.core.pipeline.policies.http_logging_policy"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

app = func.FunctionApp()


@app.timer_trigger(schedule="%SYNC_SCHEDULE%", arg_name="timer", run_on_startup=False, use_monitor=True)
async def ast_sync(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("AST sync is running late")
    await run_sync()
