package wu.wien.ac.at.encryption;


	import java.util.concurrent.Callable;
	import java.util.concurrent.CompletionService;
	import java.util.concurrent.Executor;
	import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import it.unisa.dia.gas.plaf.jpbc.util.concurrent.ExecutorServiceUtils;
import it.unisa.dia.gas.plaf.jpbc.util.concurrent.Pool;

	/**
	 * @author Angelo De Caro (jpbclib@gmail.com)
	 * @since 2.0.0
	 */
	public class PoolExec<T> implements Pool<T> {

	    protected CompletionService<T> pool;
	    protected int counter;
	    public ExecutorService ecs;


	    public PoolExec() {
	        this(ExecutorServiceUtils.getFixedThreadPool());
	    }

	    public PoolExec(Executor executor) {
	        this.pool = new ExecutorCompletionService<T>(executor);
	        this.counter = 0;
	        //this.ecs = executor;
	    }


	    @Override
		public Pool<T> submit(Callable<T> callable) {
	        counter++;
	        pool.submit(callable);

	        return this;
	    }

	    @Override
		public Pool<T> submit(Runnable runnable) {
	        counter++;
	        pool.submit(runnable, null);

	        return this;
	    }

	    @Override
		public Pool<T> awaitTermination() {
	    	ExecutorServiceUtils.shutdown();
	        try {
	            for (int i = 0; i < counter; i++)
	                pool.take().get();
	        } catch (Exception e) {
	            throw new RuntimeException(e);
	        } finally {
	            counter = 0;
	        }

	        return this;
	    }

	}
