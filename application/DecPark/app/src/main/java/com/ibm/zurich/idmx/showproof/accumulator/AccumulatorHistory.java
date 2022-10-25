//* Licensed Materials - Property of IBM                              *
//* com.ibm.zurich.idmx.2.3.40                                        *
//* (C) Copyright IBM Corp. 2013. All Rights Reserved.                *
//* US Government Users Restricted Rights - Use, duplication or       *
//* disclosure restricted by GSA ADP Schedule Contract with IBM Corp. *
//*/**/****************************************************************
package com.ibm.zurich.idmx.showproof.accumulator;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * A helper class storing a list of accumulator events for XML serialization.
 * @author enr
 *
 */
public class AccumulatorHistory implements Iterable<AccumulatorEvent> {
  private final List<AccumulatorEvent> events;
  
  public AccumulatorHistory() {
    events = new ArrayList<AccumulatorEvent>();
  }

  @Override
  public Iterator<AccumulatorEvent> iterator() {
    return events.iterator();
  }
  
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((events == null) ? 0 : events.hashCode());
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    AccumulatorHistory other = (AccumulatorHistory) obj;
    if (events == null) {
      if (other.events != null) return false;
    } else if (!events.equals(other.events)) return false;
    return true;
  }

  /**
   * Add an event to this history.
   * The event epochs must be sequential (it is OK to start with an epoch larger than 0).
   * @param event
   */
  public void addEvent(AccumulatorEvent event) {
    if (events.isEmpty()) {
      events.add(event);
    } else if (events.get(events.size()-1).getNewEpoch() + 1 == event.getNewEpoch()) {
      events.add(event);
    } else {
      throw new UnsupportedOperationException("Cannot add this event to history: non sequential epochs");
    }
  }
  
}
