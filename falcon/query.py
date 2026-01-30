"""
CrowdStrike Query Builder

A builder class for constructing CrowdStrike Falcon Query Language (FQL) queries.
"""
from typing import List, Optional, Union
from enum import Enum


class Operator(Enum):
    """Query operators for CrowdStrike FQL"""
    AND = "AND"
    OR = "OR"


class QueryBuilder:
    """
    Builder class for constructing CrowdStrike FQL queries.
    
    Supports adding multiple conditions and combining them with AND/OR operators.
    
    Example:
        >>> qb = QueryBuilder()
        >>> qb.add("event_simpleName='ProcessRollup2'")
        >>> qb.add("FileName='malware.exe'")
        >>> query = qb.build()
        >>> print(query)
        event_simpleName='ProcessRollup2' AND FileName='malware.exe'
    """
    
    def __init__(self, operator: Operator = Operator.AND):
        """
        Initialize the query builder.
        
        Args:
            operator: Default operator to combine conditions (AND or OR)
        """
        self._conditions: List[str] = []
        self._operator = operator
    
    def add(self, condition: str) -> 'QueryBuilder':
        """
        Add a search condition to the query.
        
        Args:
            condition: FQL condition string (e.g., "FileName='test.exe'")
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add("event_simpleName='ProcessRollup2'").add("FileName='cmd.exe'")
        """
        if condition and condition.strip():
            self._conditions.append(condition.strip())
        return self
    
    def add_equals(self, field: str, value: str) -> 'QueryBuilder':
        """
        Add an equality condition.
        
        Args:
            field: Field name
            value: Value to match (will be quoted)
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add_equals("FileName", "malware.exe")
            # Results in: FileName='malware.exe'
        """
        condition = f"{field}='{value}'"
        return self.add(condition)
    
    def add_contains(self, field: str, value: str) -> 'QueryBuilder':
        """
        Add a contains condition (wildcard match).
        
        Args:
            field: Field name
            value: Value to search for (wildcards will be added)
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add_contains("FileName", "malware")
            # Results in: FileName=*'malware'*
        """
        condition = f"{field}=*'{value}'*"
        return self.add(condition)
    
    def add_in(self, field: str, values: List[str]) -> 'QueryBuilder':
        """
        Add an IN condition for multiple values.
        
        Args:
            field: Field name
            values: List of values to match
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add_in("FileName", ["cmd.exe", "powershell.exe"])
            # Results in: FileName IN ('cmd.exe','powershell.exe')
        """
        if not values:
            return self
        
        quoted_values = "','".join(values)
        condition = f"{field} IN ('{quoted_values}')"
        return self.add(condition)
    
    def add_range(self, field: str, start: Union[str, int], end: Union[str, int]) -> 'QueryBuilder':
        """
        Add a range condition.
        
        Args:
            field: Field name
            start: Range start value
            end: Range end value
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add_range("ProcessId", 1000, 2000)
            # Results in: ProcessId >= 1000 AND ProcessId <= 2000
        """
        self.add(f"{field} >= {start}")
        self.add(f"{field} <= {end}")
        return self
    
    def add_group(self, conditions: List[str], operator: Optional[Operator] = None) -> 'QueryBuilder':
        """
        Add a group of conditions with parentheses.
        
        Args:
            conditions: List of conditions to group
            operator: Operator to use within the group (uses default if not specified)
            
        Returns:
            Self for method chaining
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add_group(["FileName='cmd.exe'", "FileName='powershell.exe'"], Operator.OR)
            # Results in: (FileName='cmd.exe' OR FileName='powershell.exe')
        """
        if not conditions:
            return self
        
        op = (operator or self._operator).value
        grouped = f"({f' {op} '.join(conditions)})"
        return self.add(grouped)
    
    def set_operator(self, operator: Operator) -> 'QueryBuilder':
        """
        Set the default operator for combining conditions.
        
        Args:
            operator: Operator to use (AND or OR)
            
        Returns:
            Self for method chaining
        """
        self._operator = operator
        return self
    
    def clear(self) -> 'QueryBuilder':
        """
        Clear all conditions.
        
        Returns:
            Self for method chaining
        """
        self._conditions.clear()
        return self
    
    def build(self) -> str:
        """
        Build and return the final query string.
        
        Returns:
            Complete FQL query string with all conditions combined
            
        Example:
            >>> qb = QueryBuilder()
            >>> qb.add("event_simpleName='ProcessRollup2'")
            >>> qb.add("FileName='cmd.exe'")
            >>> query = qb.build()
            >>> print(query)
            event_simpleName='ProcessRollup2' AND FileName='cmd.exe'
        """
        if not self._conditions:
            return ""
        
        operator_str = f" {self._operator.value} "
        return operator_str.join(self._conditions)
    
    def __str__(self) -> str:
        """String representation returns the built query"""
        return self.build()
    
    def __repr__(self) -> str:
        """Developer representation"""
        return f"QueryBuilder(conditions={len(self._conditions)}, operator={self._operator.value})"


def create_query() -> QueryBuilder:
    """
    Factory function to create a new QueryBuilder instance.
    
    Returns:
        New QueryBuilder instance
        
    Example:
        >>> query = create_query().add_equals("FileName", "test.exe").build()
    """
    return QueryBuilder()
