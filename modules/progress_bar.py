import sys

def print_progress_bar(iteration, total, length=50):
    """
    Prints a progress bar to the console.

    :param iteration: current iteration (int)
    :param total: total iterations (int)
    :param length: character length of the progress bar (int)
    """
    # Calculate percent completion

    # Calculate how many "blocks" of the bar should be filled
    filled_length = int(length * iteration // total)

    # Create the bar string
    bar = '█' * filled_length + '-' * (length - filled_length)

    # Print the bar
    # The carriage return (\r) moves the cursor back to the start of the line
    # end="" avoids automatic newline so that the bar updates in place
    sys.stdout.write(f'\r|{bar}| {iteration}/{total} ')
    sys.stdout.flush()

    # Print a new line when we're done
    if iteration == total:
        print()