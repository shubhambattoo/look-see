import chalk from 'chalk';

const FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const BANNER = String.raw`
 ___        ______      ______    __   ___       ________  _______   _______  
|"  |      /    " \    /    " \  |/"| /  ")     /"       )/"     "| /"     "| 
||  |     // ____  \  // ____  \ (: |/   /     (:   \___/(: ______)(: ______) 
|:  |    /  /    ) :)/  /    ) :)|    __/       \___  \   \/    |   \/    |   
 \  |___(: (____/ //(: (____/ // (// _  \        __/  \\  // ___)_  // ___)_  
( \_|:  \\        /  \        /  |: | \  \      /" \   :)(:      "|(:      "| 
 \_______)"\_____/    "\_____/   (__|  \__)    (_______/  \_______) \_______)  
`.trim();

export function createProgress(io = console, { interactive = Boolean(process.stdout.isTTY) } = {}) {
  let timer = null;
  let frame = 0;
  let label = '';

  function clearLine() {
    process.stdout.write('\r\u001b[2K');
  }

  function stopSpinner() {
    if (timer) clearInterval(timer);
    timer = null;
    if (interactive) clearLine();
  }

  function render() {
    if (!interactive || !label) return;
    const icon = FRAMES[frame++ % FRAMES.length];
    process.stdout.write(`\r\u001b[2K${chalk.cyan(icon)} ${label}`);
  }

  function start(message) {
    stopSpinner();
    label = message;
    if (interactive) {
      render();
      timer = setInterval(render, 90);
      timer.unref?.();
    } else {
      io.log(chalk.cyan(`› ${message}`));
    }
  }

  function banner() {
    io.log(chalk.bold.cyan(BANNER));
  }

  function update(message) {
    label = message;
    if (interactive) render();
    else io.log(chalk.dim(`  ${message}`));
  }

  function complete(message) {
    stopSpinner();
    label = '';
    io.log(chalk.green(`✓ ${message}`));
  }

  function warn(message) {
    stopSpinner();
    label = '';
    io.warn?.(chalk.yellow(`! ${message}`));
  }

  function skip(message) {
    stopSpinner();
    label = '';
    io.log(chalk.dim(`– ${message}`));
  }

  function note(message) {
    io.log(message);
  }

  return { banner, start, update, complete, warn, skip, note, stop: stopSpinner };
}

export const progressHelpers = { BANNER };
