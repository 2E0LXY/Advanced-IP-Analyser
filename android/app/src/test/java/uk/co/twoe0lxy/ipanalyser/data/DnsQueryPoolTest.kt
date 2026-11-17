package uk.co.twoe0lxy.ipanalyser.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

class DnsQueryPoolTest {
  @Test
  fun excessQueriesAreRejectedInsteadOfQueuedWithoutLimit() {
    val pool = boundedQueryPool(threads = 2, queueCapacity = 3)
    val release = CountDownLatch(1)
    val started = CountDownLatch(2)
    try {
      repeat(2) { pool.execute { started.countDown(); release.await(10, TimeUnit.SECONDS) } }
      assertTrue(started.await(5, TimeUnit.SECONDS))
      repeat(3) { pool.execute { release.await(10, TimeUnit.SECONDS) } }
      assertEquals(3, pool.queue.size)
      assertThrows(RejectedExecutionException::class.java) { pool.execute { } }
      assertEquals(3, pool.queue.size)
    } finally {
      release.countDown()
      pool.shutdownNow()
    }
  }
}
